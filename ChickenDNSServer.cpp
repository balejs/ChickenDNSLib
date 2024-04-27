#include <ChickenDNSServer.h>
#include <LoopScheduler.h>

#if DNS_SERVER_LOG_LEVEL > 0
#define TAG "DNSServer"
#endif
#include <DebugFuncs.h>

extern "C"
{
#include <sys/time.h>
#include "string.h"
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "esp_netif.h"
}

#define MAX_MSG_LEN 512

// from https://www.ietf.org/rfc/rfc1035.txt (DNS protocol)
//      https://www.ietf.org/rfc/rfc7553.txt (URI DNS Resource Record)

// example DNS message for testing: https://routley.io/posts/hand-writing-dns-messages
// also see https://jameshfisher.com/2016/12/31/dns-protocol/

// Section 3.2.2
typedef enum
{
  DNS_Q_TYPE_A = 1,      //  a host address
  DNS_Q_TYPE_NS = 2,     //  an authoritative name server
  DNS_Q_TYPE_MD = 3,     //  a mail destination (Obsolete - use MX)
  DNS_Q_TYPE_MF = 4,     //  a mail forwarder (Obsolete - use MX)
  DNS_Q_TYPE_CNAME = 5,  //  the canonical name for an alias
  DNS_Q_TYPE_SOA = 6,    //  marks the start of a zone of authority
  DNS_Q_TYPE_MB = 7,     //  a mailbox domain name (EXPERIMENTAL)
  DNS_Q_TYPE_MG = 8,     //  a mail group member (EXPERIMENTAL)
  DNS_Q_TYPE_MR = 9,     //  a mail rename domain name (EXPERIMENTAL)
  DNS_Q_TYPE_NULL = 10,  //  a null RR (EXPERIMENTAL)
  DNS_Q_TYPE_WKS = 11,   //  a well known service description
  DNS_Q_TYPE_PTR = 12,   //  a domain name pointer
  DNS_Q_TYPE_HINFO = 13, //  host information
  DNS_Q_TYPE_MINFO = 14, //  mailbox or mail list information
  DNS_Q_TYPE_MX = 15,    //  mail exchange
  DNS_Q_TYPE_TXT = 16,   //  text strings
  DNS_Q_TYPE_URI = 256,  //  URI (RFC7553)
} QType;

// 4.1.1. Header section format
#define DNS_HEADER_LENGTH 96
#define DNS_HEADER_ID 0
#define DNS_HEADER_QR 16
#define DNS_HEADER_OPCODE 17
#define DNS_HEADER_AA 21
#define DNS_HEADER_TC 22
#define DNS_HEADER_RD 23
#define DNS_HEADER_RA 24
#define DNS_HEADER_Z 25
#define DNS_HEADER_RCODE 28
#define DNS_HEADER_QDCOUNT 32
#define DNS_HEADER_ANCOUNT 48
#define DNS_HEADER_NSCOUNT 64
#define DNS_HEADER_ARCOUNT 80

typedef enum
{
  DNS_RCODE_NO_ERR = 0,
  DNS_RCODE_FORMAT_ERR = 1,
  DNS_RCODE_SERVER_FAILURE = 2,
  DNS_RCODE_NAME_ERR = 3,
  DNS_RCODE_NOT_IMPL = 4,
  DNS_RCODE_REFUSED = 5
} RCode;

// 4.1.2. Question section format

#define DNS_CLASS_IN (1)
#define DNS_Q_CLASS_ANY (255)

// TODO: where is this defined? found from wireshark
#define DNS_CLASS_URI (256)

// 4.1.3. Resource record format

#define DNS_RESOURCE_RECORD_LENGTH 80
#define DNS_RESOURCE_RECORD_TYPE 0
#define DNS_RESOURCE_RECORD_CLASS 16
#define DNS_RESOURCE_RECORD_TTL 32
#define DNS_RESOURCE_RECORD_RDLENGTH 64

#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
using namespace Chicken;

#define HEADER_LEN (12)

namespace Chicken
{
  class DNSMessage : public FillableBuf
  {
  public:
    DNSMessage() : FillableBuf() {}
    DNSMessage(DNSMessage *other) : FillableBuf(other) {}

    esp_err_t appendResourceRecord(ChickenStr qName, QType qType, uint16_t qClass, uint16_t rdLength)
    {
      uint16_t anCount = getU16(DNS_HEADER_ANCOUNT);
      // 4.1.3. Resource record format
      // TODO: use compressed format and just add C0 0C ?
      esp_err_t err = appendLabel(qName); // NAME
      checkout("Unable to set label in reply");

      logln("Resource Record before modifying bytes:");
      logDump();

      // Append the remaining Resource Record values
      err = setU16(qType); // TYPE
      checkout("Unable to reply type");
      err = setU16(qClass); // CLASS
      checkout("Unable to reply class");
      err = setU32(0); // TTL
      checkout("Unable to reply ttl");
      err = setU16(rdLength); // RDLENGTH
      checkout("Unable to reply rdlength");

      setU16(anCount + 1, DNS_HEADER_ANCOUNT);

      _getout

      return err;
    }

    bool isValid()
    {
      if (getTotalLength() == 0)
      {
        return false;
      }

      uint32_t lengthBytes = getLength();

      if (lengthBytes > CHICKEN_SOCKET_MAX_MSG_LEN || lengthBytes < HEADER_LEN)
      {
        logln("Message has incorrect length (%d)", lengthBytes);
        return false;
      }

      if (getU16(DNS_HEADER_ANCOUNT) || getU16(DNS_HEADER_NSCOUNT) || getU16(DNS_HEADER_ARCOUNT))
      {
        logln("Can't handle reply messages");
        return false;
      }

      if (getBit(DNS_HEADER_TC))
      {
        logln("Can't handle truncated messages");
        return false;
      }

      return true;
    }

#define LABEL_TYPE_UNKNOWN (0)
#define LABEL_TYPE_MASK (0xc0)
#define LABEL_TYPE_POINTER (0xc0)
#define LABEL_TYPE_STRING (0)

    // beginPosition is an inout parameter and is updated with the first pos after the label
    esp_err_t getLabel(uint16_t *endpointBitsInOut, ChickenStr labelOut)
    {
      uint8_t labelType = LABEL_TYPE_UNKNOWN;

      esp_err_t err = ESP_OK;
      bool addSeparator = false;
      uint16_t posBytes = *endpointBitsInOut / 8; // According to the rfc it always starts on byte boundaries

      // 4.1.4 Message compression, pointer
      //[...] The compression scheme allows a domain name in a message to be represented as either:
      //- a sequence of labels ending in a zero octet
      //- a pointer
      //- a sequence of labels ending with a pointer
      logln("initial pos: %u type: %u", posBytes, labelType);

      while (posBytes < getLength() && labelType != LABEL_TYPE_POINTER && d()[posBytes] != 0)
      {
        labelType = d()[posBytes] & LABEL_TYPE_MASK;

        logln("pos: %u type: %u", posBytes, labelType);

        if (labelType == LABEL_TYPE_POINTER)
        {
          // Shift the most significant byte by 5 because 2 bits of the lsb are used for the type
          uint16_t offset = (((uint16_t)d()[posBytes + 1]) << 5) | ((uint16_t)(d()[posBytes] & (~LABEL_TYPE_MASK)));
          *endpointBitsInOut += 16;

          if (offset >= getLength())
          {
            bailout(ESP_ERR_INVALID_ARG, "Invalid offset in domain name: %d, message length: %d", offset, lengthBytes);
          }

          posBytes = offset / 8;
        }
        else if (labelType != LABEL_TYPE_STRING)
        {
          bailout(ESP_ERR_INVALID_ARG, "Unknown label type (0x%x), bailing out", labelType);
        }

        uint8_t labelLength = d()[posBytes++]; // restricted to 63 octects or less
        logln("pos: %u length: %u", posBytes - 1, labelLength);
        *endpointBitsInOut += (labelLength + 1) * 8; // bits in the label + length byte

        // 2.3.1. Preferred name syntax
        if (addSeparator)
        {
          logln("separator");
          labelOut->append(".");
        }

        logln("appending %c from pos %u", *((char *)message + posBytes), posBytes);
        labelOut->append((char *)d() + posBytes, labelLength);
        addSeparator = true;
        posBytes += labelLength;
      }

      if (labelType == LABEL_TYPE_STRING)
      {
        *endpointBitsInOut += 8; // trailing zero
      }

      _getout return err;
    }

    esp_err_t appendString(ChickenStr str)
    {
      esp_err_t err = ESP_OK;
      if (getLength() + str->getLength() + 1 > getSize())
      {
        checkout("Unable to store string of length %d at pos %d (total size: %d)", str->getLength(), lengthBytes, sizeof(message));
      }

      memcpy(d() + getLength(), str->c(), str->getLength() + 1);

      _getout return err;
    }

    esp_err_t appendLabel(ChickenStr label)
    {
      uint16_t lenPos = getLength(); // the byte at lenPos contains the string length
      uint16_t pos = lenPos + 1;
      esp_err_t err = ESP_OK;

      for (char *str = label->c(); *str != '\0' && pos < getSize(); str++, pos++)
      {
        if (*str == '.')
        {
          d()[lenPos] = pos - lenPos - 1;
          lenPos = pos;
        }
        else
        {
          d()[pos] = *str;
        }
      }

      d()[lenPos] = pos - lenPos - 1;

      if (pos < getSize() - 1)
      {
        d()[pos] = '\0';
        ensureLength(pos + 1);
      }
      else
      {
        ensureLength(getSize());
        bailout(ESP_ERR_INVALID_ARG, "Label %s falls outside message boundaries", label->c());
      }

      _getout return err;
    }
  };
}

Chicken::DNSServer::DNSServer(ChickenStr domainName, SLoopScheduler loopScheduler)
{
  _domainName = domainName;
  _loopScheduler = loopScheduler;

  _serverSocket = Socket::make(loopScheduler);
  SDNSMessage message = MakeDNSMessage();

  auto weakPtr = _weakPtr;
  _serverSocket->receive([weakPtr](esp_err_t err, SBuf message) -> esp_err_t
  {
    checkout("Error getting DNS message from socket");
    err = lockOrDie(weakPtr, err, [message](esp_err_t err, SDNSServer sharedPtr) -> esp_err_t
    {
      return sharedPtr->handleMessage(std::static_pointer_cast<DNSMessage>(message));
    });

    _getout
    return err;
  });

  _running = true;
}

esp_err_t Chicken::DNSServer::handleMessage(SDNSMessage message)
{
  SDNSMessage reply = MakeDNSMessage(message.get());
  reply->setBit(DNS_HEADER_QR, 1);

  // 4.1.1. Header section format
  uint16_t qdCount = message->getU16(DNS_HEADER_QDCOUNT);
  uint16_t posBits = DNS_HEADER_LENGTH;
  esp_err_t err = ESP_OK;

  for (uint16_t i = 0; i < qdCount; i++)
  {
    // 4.1.2 Question section format
    ChickenStr qName = MakeChickenStr();
    uint16_t qType, qClass;
    (void)qClass; // suppress unused variable warning when building without logs

    err = message->getLabel(&posBits, qName);
    checkout("Unable to read label at pos %u", posBits);

    qType = message->getU16(posBits);
    posBits += 16;
    qClass = message->getU16(posBits);
    posBits += 16;

    logln("Question: type 0x%X class 0x%X name: %s\n", qType, qClass, qName->c() == NULL ? "(null)" : qName->c());

    switch (qType)
    {
    case DNS_Q_TYPE_A:
    {
      err = reply->appendResourceRecord(qName, DNS_Q_TYPE_A, DNS_CLASS_IN, 4);

      checkout("Unable to append query type A");

      // 3.4.1. A RDATA format
      esp_netif_ip_info_t addr;
      esp_netif_get_ip_info(esp_netif_next(NULL), &addr);
      err = reply->setU32(ntohl(addr.ip.addr)); // ADDRESS
    }
    break;
    case DNS_Q_TYPE_NS:
    {
      err = reply->appendResourceRecord(qName, DNS_Q_TYPE_NS, DNS_CLASS_IN, 4);
      checkout("Unable to append query type NS");

      // 3.3.11. NS RDATA format
      ChickenStr nameServer = MakeChickenStr("hi"); // this will use 1 byte for the length + 3 bytes for the string
      err = reply->appendLabel(nameServer);         // NSDNAME
    }
    break;
    case DNS_Q_TYPE_URI:
    {
      // rdlength is 4 (uri header) + domain name length + 2 (the double quotes)
      err = reply->appendResourceRecord(qName, DNS_Q_TYPE_URI, DNS_CLASS_URI, 4 + _domainName->getLength() + 2);

      // RFC7553 4.5.  URI RDATA Wire Format
      err = reply->setU16(10); // Priority (value taken from the example)
      err = reply->setU16(1);  // Weight (value taken from the example)

      // Target, as specified in RFC7553 section 4.4
      err = reply->setU8('"');
      err = reply->appendString(_domainName);
      err = reply->setU8('"');
    }
    break;
    default:
      logln("Unhandled query type: %d", qType);
    }
  }

  err = _serverSocket->send(reply, [](esp_err_t err) -> esp_err_t
  {
    logln("DNS response error code: %s", esp_err_to_name(err));
    return err;
  });

  _getout
  return err;
}
