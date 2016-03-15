/*
 * mdns-register.cpp
 *
 *  Created on: Mar 15, 2016
 *      Author: Dmitri Rubinstein
 */

#include "MDNSManager.hpp"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>

using namespace MDNS;

#define ARG(str) (!strcmp(argv[i], str))
#define ARG_STARTS_WITH(str,len) (!strncmp(argv[i], str, len))
#define ARG_CONTAINS(str) strstr(argv[i], str)
#define APP_ERROR(msg) { if (!quiet) std::cerr<<msg<<std::endl; exit(1); }

void printUsageInfo()
{
    std::cout << "mdns-register [options]\n\n"
                 "options:\n"
                 "  -h | --help                                            : print this and exit\n"
                 "  -q | --quiet                                           : do not print messages\n"
                 "  -s | --service name type domain port [key=value ...]   : register service\n"
                 "Note: use syntax '=-...=value' in order to specify keys that starts with '-' character."
              << std::endl;
}

int main(int argc, char **argv)
{
    std::vector<MDNSService> services;

    bool quiet = false;

    // parse command line
    int i;
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            if (ARG("--help") || ARG("-h"))
            {
                printUsageInfo();
                exit(0);
            }
            else if (ARG("-q") || ARG("--quiet"))
            {
                quiet = true;
            }
            else if (ARG("--service") || ARG("-s"))
            {
                if (i+4 < argc)
                {
                    MDNSService service;
                    service.setName(argv[++i]);
                    service.setType(argv[++i]);
                    service.setDomain(argv[++i]);
                    int port = atoi(argv[++i]);
                    if (port < 0 || port > 65535)
                    {
                        APP_ERROR("port number "<<port<<" out of range");
                    }
                    service.setPort(port);

                    while (++i < argc)
                    {
                        if (argv[i][0] == '-')
                        {
                            --i;
                            break;
                        }
                        const char * arg = argv[i][0] == '=' ? argv[i]+1 : argv[i];
                        service.addTxtRecord(arg);
                    }
                    services.push_back(std::move(service));
                }
                else
                {
                    APP_ERROR(argv[i]<<" option require four arguments");
                }
            }
            else
            {
                APP_ERROR("Invalid option: "<<argv[i]);
            }
        }
        else
        {
            APP_ERROR("Invalid argument: "<<argv[i]);
        }
    }

    if (services.empty())
    {
        APP_ERROR("No services specified");
    }

    MDNSManager mgr;

    for (auto it = services.begin(), eit = services.end(); it != eit; ++it)
    {
        if (!quiet)
        {
            const auto & service = *it;
            std::cout<<"Register service '"<<service.getName()<<"' of type '"<<service.getType()<<"' on domain "<<service.getDomain()
                     <<" (interface: "<<service.getInterfaceIndex()<<", host: "<<service.getHost()
                     <<", port "<<service.getPort()<<")"<<std::endl;
            if (!service.getTxtRecords().empty())
            {
                std::cout<<"  TXT ["<<std::endl;
                for (auto it = service.getTxtRecords().begin(), iend = service.getTxtRecords().end(); it != iend; ++it)
                {
                    std::cout<<"    "<<*it<<std::endl;
                }
                std::cout<<"  ]"<<std::endl;
            }
        }

        mgr.registerService(*it);
    }

    mgr.run();

    std::cin.get();
}
