#ifndef __CHICKEN_DNS_SERVER_H__
#define __CHICKEN_DNS_SERVER_H__

#include <memory>
#include <lwip/ip4_addr.h>

#include <Buffering.h>
#include <ChickenSocket.h>
#include <LoopScheduler.h>

namespace Chicken {
    class DNSMessage;
    DefineHelpers(DNSMessage);

    class DNSServer: public Weakling<DNSServer>
    {
        public:
            DNSServer(SStr domainName, SLoopScheduler loopScheduler);

        private:
            SStr _domainName;
            bool _running;

            SLoopScheduler _loopScheduler;
            SSocket _serverSocket;

            esp_err_t handleMessage(SDNSMessage message);

            uint16_t networkToHostOrder(uint16_t networkOrder)
            {
                return ((networkOrder & 0xff) << 8) | ((networkOrder & 0xff00) >> 8);
            }
    };

    DefineHelpers(DNSServer);
}

#endif //__CHICKEN_DNS_SERVER_H__