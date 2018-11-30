#include <thread>
#include <validation.h>
#include <ui_interface.h>
#include <util.h>
#include <memory>

#include "status_sender.h"
#include "wallet/wallet.h"

#include <support/events.h>
#include <event2/buffer.h>
#include <rpc/client.h>

namespace
{
    std::mutex mutex;
    const auto Timeout = std::chrono::milliseconds(200);
    const auto data_send_interval = std::chrono::minutes(15); // time interval between sending data
    const int http_timeout = 10; // sec
    bool running = false;
    CWallet* wallet = nullptr;
    std::thread thread;

    /** Reply structure for request_done to fill in */
    struct HTTPReply
    {
        HTTPReply(): status(0), error(-1) {}

        int status;
        int error;
        std::string body;
    };

    static void http_request_done(struct evhttp_request *req, void *ctx)
    {
        HTTPReply *reply = static_cast<HTTPReply*>(ctx);

        if (req == nullptr) {
            /* If req is nullptr, it means an error occurred while connecting: the
             * error code will have been passed to http_error_cb.
             */
            reply->status = 0;
            return;
        }

        reply->status = evhttp_request_get_response_code(req);

        struct evbuffer *buf = evhttp_request_get_input_buffer(req);
        if (buf)
        {
            size_t size = evbuffer_get_length(buf);
            const char *data = (const char*)evbuffer_pullup(buf, size);
            if (data)
                reply->body = std::string(data, size);
            evbuffer_drain(buf, size);
        }
    }

    void send_data(std::string lynxhost, std::string ip, int curHeight, bool wallet_enabled, bool is_Raspberry_Pi, std::string host, int port)
    {
        HTTPReply response;
        raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
        if (req == nullptr)
        {
            // create http request failed
            return;
        }

        UniValue params(UniValue::VOBJ);
        params.pushKV("host", lynxhost);
        params.pushKV("ip", ip);
        params.pushKV("height", curHeight);
        params.pushKV("wallet", wallet_enabled ? 1: 0);
        params.pushKV("RPI", is_Raspberry_Pi ? 1: 0);
        std::string strRequest = params.write() + "\n";

        struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
        assert(output_buffer);
        evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

        std::string endpoint = "/";

        // Obtain event base
        raii_event_base base = obtain_event_base();
        // Synchronously look up hostname
        raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
        evhttp_connection_set_timeout(evcon.get(), http_timeout);
        evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, endpoint.c_str());
        event_base_dispatch(base.get());
        req.release(); // ownership moved to evcon in above call
    }

    void get_data(std::string& lynxhost, std::string& ip, int& curHeight, int& wallet_enabled, int& is_Raspberry_Pi)
    {
        lynxhost = gArgs.GetArg("-host", std::string());
        ip = gArgs.GetArg("-bind", std::string());

        {
            LOCK(cs_main);
            curHeight = chainActive.Height();
        }

        wallet_enabled = !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);

#ifdef HAVE__OPT_VC_INCLUDE_BCM_HOST_H
        is_Raspberry_Pi = 1;
#else
        is_Raspberry_Pi = 0;
#endif
    }

    void send_status()
    {
        std::string lynxhost;
        std::string ip;
        int curHeight;
        int wallet_enabled;
        int is_Raspberry_Pi;

        get_data(lynxhost, ip, curHeight, wallet_enabled, is_Raspberry_Pi);
        send_data(lynxhost, ip, curHeight, wallet_enabled, is_Raspberry_Pi, "node01.getlynx.io", 8080);
        send_data(lynxhost, ip, curHeight, wallet_enabled, is_Raspberry_Pi, "node02.getlynx.io", 8080);
        send_data(lynxhost, ip, curHeight, wallet_enabled, is_Raspberry_Pi, "node03.getlynx.io", 8080);
    }

    void routine()
    {
        while (running)
        {
            auto start = std::chrono::system_clock::now();
            send_status();

            std::string debug_arg = gArgs.GetArg("-debug", std::string());
            if ((debug_arg == "all") || (debug_arg == "1"))
            {
                LogPrint(BCLog::ALL, "Network efficiency polling packet sent.\n");
            }

            auto end = std::chrono::system_clock::now();
            std::chrono::duration<double> send_time = end - start;
            auto sleep_time = data_send_interval - send_time;

            if (sleep_time > Timeout)
            {
                // loop here is to be able to stop faster if "running" has changed
                for (int i = 0; running && i < static_cast<int>(sleep_time / Timeout); i++)
                    std::this_thread::sleep_for(Timeout);
            }
        }
    }

    void doStart()
    {
        running = true;
        thread = std::thread(routine);
    }

    void doStop()
    {
        running = false;
        thread.join();
    }
}

void StatusSender::start()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (running)
        return; // Unable to start the status sender: the status sender is active

    try
    {
        doStart();
    }
    catch (...)
    {
        doStop();
        throw;
    }
}

void StatusSender::stop()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (running)
    {
        doStop();
    }
}

bool StatusSender::appInit()
{
    try
    {
        start();
    }
    catch (const std::exception& e)
    {
        return InitError(e.what());
    }

    return true;
}

bool StatusSender::isRunning()
{
    std::lock_guard<std::mutex> lock(mutex);
    return running;
}
