#ifndef __CHICKEN_DNS_SERVER_H__
#define __CHICKEN_DNS_SERVER_H__

#include <ChickenStr.h>
#include <memory>
#include <lwip/ip4_addr.h>
#include <ChickenSocket.h>
#include <LoopScheduler.h>
#include <Interfaces.h>


namespace Chicken {
    class DNSMessage;
    DefineHelpers(DNSMessage);

    class DNSServer: public Weakling<DNSServer>
    {
        public:
            DNSServer(ChickenStr domainName, SLoopScheduler loopScheduler);

        private:
            ChickenStr _domainName;
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