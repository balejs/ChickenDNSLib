#ifndef __CHICKEN_DNS_SERVER_H__
#define __CHICKEN_DNS_SERVER_H__

#include <ChickenStr.h>
#include <memory>
#include <lwip/ip4_addr.h>
#include <ChickenSocket.h>
#include <Interfaces.h>


class LoopScheduler;

namespace Chicken {
    class DNSMessage;

    class DNSServer: public Weakling<DNSServer>
    {
        public:
            DNSServer(ChickenStr domainName, std::shared_ptr<LoopScheduler> loopScheduler);

        private:
            ChickenStr domainName;
            bool running;

            std::shared_ptr<LoopScheduler> loopScheduler;
            std::shared_ptr<Socket> serverSocket;

            esp_err_t handleMessage(std::shared_ptr<DNSMessage> message);

            uint16_t networkToHostOrder(uint16_t networkOrder)
            {
                return ((networkOrder & 0xff) << 8) | ((networkOrder & 0xff00) >> 8);
            }
    };
}

#endif //__CHICKEN_DNS_SERVER_H__