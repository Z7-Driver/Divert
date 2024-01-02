#include <net/NetWorkChangeNotifier.h>
#include <common/log/blog.h>
namespace net
{
    typedef
        VOID
        (WINAPI* PIPINTERFACE_CHANGE_CALLBACK) (
            _In_ PVOID CallerContext,
            _In_ PMIB_IPINTERFACE_ROW Row OPTIONAL,
            _In_ MIB_NOTIFICATION_TYPE NotificationType
            );
    typedef DWORD(WINAPI* pfnNotifyIpInterfaceChange)(
        _In_ ADDRESS_FAMILY Family,
        _In_ PIPINTERFACE_CHANGE_CALLBACK Callback,
        _In_opt_ PVOID CallerContext,
        _In_ BOOLEAN InitialNotification,
        _Inout_ HANDLE* NotificationHandle
        );
    typedef DWORD(WINAPI* pfnCancelMibChangeNotify2)(
        _In_ HANDLE NotificationHandle
        );
    static HMODULE sIphlpapi = nullptr;


    static pfnNotifyIpInterfaceChange sNotifyIpInterfaceChange = nullptr;
    static pfnCancelMibChangeNotify2 sCancelMibChangeNotify2 = nullptr;



    HRESULT STDMETHODCALLTYPE CNetworkListManagerEvent::ConnectivityChanged(
        /* [in] */ NLM_CONNECTIVITY newConnectivity)
    {
        network_change_monitor_->ConnectivityChanged(newConnectivity);
        return S_OK;
    }


    NetworkChangeMonitor::NetworkChangeMonitor()
    {
    }

    NetworkChangeMonitor::~NetworkChangeMonitor()
    {
        if (interfacechange_shutdown_event_)
        {
            CloseHandle(interfacechange_shutdown_event_);
            interfacechange_shutdown_event_ = nullptr;
        }
    }
    void NetworkChangeMonitor::Initialize()
    {

    }
    void NetworkChangeMonitor::UnInitialize()
    {

    }

    bool NetworkChangeMonitor::RegisterNetworkChangeCallback(INetworkChangeCallback* callback)
    {
        {

            std::unique_lock<std::shared_mutex> lck(callback_list_mutex_);
            callback_list_.push_back(callback);
            lck.unlock();
        }
        bool ret = true;
        if (!StartNLMInterfaceMonitor())
        {
            BLOG(ERRORB) << u8"StartNLMInterfaceMonitor fail,errcode:" << GetLastError();
        }
        if (!StartInterfaceChangeMonitor())
        {
            BLOG(ERRORB) << u8"StartInterfaceChangeMonitor fail,errcode:" << GetLastError();
        }
        return ret;
    }

    void NetworkChangeMonitor::UnRegisterNetworkChangeCallback(INetworkChangeCallback* callback)
    {
        {

            std::unique_lock<std::shared_mutex> lck(callback_list_mutex_);
            for (auto iter = callback_list_.begin(); iter != callback_list_.end(); iter++)
            {
                if (*iter == callback)
                {
                    callback_list_.erase(iter);
                    break;
                }
            }
            lck.unlock();
        }
        if (callback_list_.size() == 0)
        {
            StopNLMInterfaceMonitor();
            StopInterfaceChangeMonitor();
        }
    }
    std::ostream& operator<<(std::ostream& os, const NLM_CONNECTIVITY& nlm_type)
    {
        if (NLM_CONNECTIVITY_DISCONNECTED == nlm_type)
        {
            os << u8"DISCONNECTED/";
        }
        if ((NLM_CONNECTIVITY_IPV4_NOTRAFFIC & nlm_type) == NLM_CONNECTIVITY_IPV4_NOTRAFFIC)
        {
            os << u8"IPV4_NOTRAFFIC/";
        }
        if ((NLM_CONNECTIVITY_IPV6_NOTRAFFIC & nlm_type) == NLM_CONNECTIVITY_IPV6_NOTRAFFIC)
        {
            os << u8"IPV6_NOTRAFFIC/";
        }
        if ((NLM_CONNECTIVITY_IPV4_SUBNET & nlm_type) == NLM_CONNECTIVITY_IPV4_SUBNET)
        {
            os << u8"_IPV4_SUBNET/";
        }
        if ((NLM_CONNECTIVITY_IPV4_LOCALNETWORK & nlm_type) == NLM_CONNECTIVITY_IPV4_LOCALNETWORK)
        {
            os << u8"IPV4_LOCALNETWORK/";
        }

        if ((NLM_CONNECTIVITY_IPV4_INTERNET & nlm_type) == NLM_CONNECTIVITY_IPV4_INTERNET)
        {
            os << u8"IPV4_INTERNET/";
        }
        if ((NLM_CONNECTIVITY_IPV6_SUBNET & nlm_type) == NLM_CONNECTIVITY_IPV6_SUBNET)
        {
            os << u8"IPV6_SUBNET/";
        }
        if ((NLM_CONNECTIVITY_IPV6_LOCALNETWORK & nlm_type) == NLM_CONNECTIVITY_IPV6_LOCALNETWORK)
        {
            os << u8"IPV6_LOCALNETWORK/";
        }
        if ((NLM_CONNECTIVITY_IPV6_INTERNET & nlm_type) == NLM_CONNECTIVITY_IPV6_INTERNET)
        {
            os << u8"IPV6_INTERNET/";
        }
        return os;
    }
    void NetworkChangeMonitor::ConnectivityChanged(/* [in] */ NLM_CONNECTIVITY newConnectivity)
    {

        BLOG(INFO) << u8"Receive NetWork change " << newConnectivity;
    }
    bool NetworkChangeMonitor::StartNLMInterfaceMonitor()
    {
        if (!is_monitor_NLM_.exchange(true))
        {
            uint32_t thread_id = 0;
            netchange_monitor_nlm_thread_handle_ = (HANDLE)_beginthreadex(NULL, 0, MonitorNetworkChangeThread, this, 0, &thread_id);
        }
        return is_monitor_NLM_.load();
    }
    bool NetworkChangeMonitor::StartInterfaceChangeMonitor()
    {

        if (!is_monitor_interface_change_.exchange(true))
        {
            if (!sIphlpapi) {
                sIphlpapi = LoadLibraryW(L"Iphlpapi.dll");
                if (sIphlpapi) {
                    sNotifyIpInterfaceChange = (pfnNotifyIpInterfaceChange)
                        GetProcAddress(sIphlpapi, "NotifyIpInterfaceChange");
                    sCancelMibChangeNotify2 = (pfnCancelMibChangeNotify2)
                        GetProcAddress(sIphlpapi, "CancelMibChangeNotify2");
                }
                else {
                    BLOG(ERRORB) << u8"Failed to load Iphlpapi.dll - cannot detect network  changes!";
                }
            }
            if (interfacechange_shutdown_event_ == nullptr)
            {

                interfacechange_shutdown_event_ = CreateEvent(nullptr, false, false, nullptr);
            }
            uint32_t thread_id = 0;
            netchange_monitor_ipchange_thread_handle_ = (HANDLE)_beginthreadex(NULL, 0, MonitorInterfaceChangeThread, this, 0, &thread_id);
        }
        return is_monitor_interface_change_.load();
    }
    bool NetworkChangeMonitor::StopNLMInterfaceMonitor()
    {

        if (is_monitor_NLM_.exchange(false))
        {
            if (netchange_monitor_nlm_thread_handle_)
            {
                CloseHandle(netchange_monitor_nlm_thread_handle_);
                netchange_monitor_nlm_thread_handle_ = nullptr;
            }
        }
        return !is_monitor_NLM_.load();
    }
    bool NetworkChangeMonitor::StopInterfaceChangeMonitor()
    {

        if (is_monitor_interface_change_.exchange(false))
        {
            if (netchange_monitor_ipchange_thread_handle_)
            {
                CloseHandle(netchange_monitor_ipchange_thread_handle_);
                netchange_monitor_ipchange_thread_handle_ = nullptr;
            }
            if (sIphlpapi)
            {
                FreeLibrary(sIphlpapi);
                sIphlpapi = nullptr;
            }
            if (interfacechange_shutdown_event_)
            {
                SetEvent(interfacechange_shutdown_event_);
            }
        }
        return !is_monitor_interface_change_.load();
    }

    unsigned __stdcall NetworkChangeMonitor::MonitorInterfaceChangeThread(void* param)
    {

        unsigned ret = reinterpret_cast<NetworkChangeMonitor*>(param)->MonitorInterfaceChangeRunner();
        _endthreadex(ret);
        return ret;
    }

    std::ostream& operator<<(std::ostream& os, const MIB_NOTIFICATION_TYPE& NotificationTyp)
    {
        if (MIB_NOTIFICATION_TYPE::MibAddInstance == NotificationTyp)
        {
            os << u8"MibAddInstance";
        }
        else if (MIB_NOTIFICATION_TYPE::MibParameterNotification == NotificationTyp)
        {
            os << u8"MibParameterNotification";
        }
        else if (MIB_NOTIFICATION_TYPE::MibDeleteInstance == NotificationTyp)
        {
            os << u8"MibDeleteInstance";
        }
        else if (MIB_NOTIFICATION_TYPE::MibInitialNotification == NotificationTyp)
        {
            os << u8"MibInitialNotification";
        }
        return os;
    }
    VOID NetworkChangeMonitor::InterfaceChangeCallbackImpl(_In_ PMIB_IPINTERFACE_ROW Row OPTIONAL, _In_ MIB_NOTIFICATION_TYPE NotificationTyp)
    {
        BLOG(INFO) << u8"interface change NotificationTyp:" << NotificationTyp;

    }
    VOID __stdcall NetworkChangeMonitor::InterfaceChangeCallback(
        _In_ PVOID CallerContext,
        _In_ PMIB_IPINTERFACE_ROW Row OPTIONAL,
        _In_ MIB_NOTIFICATION_TYPE NotificationType
    )
    {
        NetworkChangeMonitor* pThis = (NetworkChangeMonitor*)CallerContext;
        pThis->InterfaceChangeCallbackImpl(Row, NotificationType);
    }
    unsigned NetworkChangeMonitor::MonitorInterfaceChangeRunner()
    {


        // Windows Vista and newer versions.
        HANDLE interfacechange = nullptr;
        // The callback will simply invoke CheckLinkStatus()
        DWORD ret = sNotifyIpInterfaceChange(
            AF_UNSPEC, // IPv4 and IPv6
            InterfaceChangeCallback,
            this,  // pass to callback
            false, // no initial notification
            &interfacechange);

        if (ret == NO_ERROR) {
            ret = WaitForSingleObject(interfacechange_shutdown_event_, INFINITE);
        }
        (*sCancelMibChangeNotify2)(interfacechange);
        return 0;
    }
    unsigned __stdcall NetworkChangeMonitor::MonitorNetworkChangeThread(void* param)
    {
        unsigned ret = reinterpret_cast<NetworkChangeMonitor*>(param)->MonitorNetworkChangeRunner();
        _endthreadex(ret);
        return ret;
    }
    unsigned NetworkChangeMonitor::MonitorNetworkChangeRunner()
    {
        unsigned retval = -1;

        HRESULT hrComInit = CoInitialize(NULL);
        if (FAILED(hrComInit))
        {
            BLOG(ERRORB) << u8"CoInitialize Fail,hr:" << hrComInit;
            return retval;
        }
        IUnknown* pUnknown = NULL;
        HRESULT Result = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_IUnknown, (void**)&pUnknown);
        if (SUCCEEDED(Result))
        {
            INetworkListManager* pNetworkListManager = NULL;
            Result = pUnknown->QueryInterface(IID_INetworkListManager, (void**)&pNetworkListManager);
            if (SUCCEEDED(Result))
            {
                IConnectionPointContainer* pCPContainer = NULL;
                Result = pNetworkListManager->QueryInterface(IID_IConnectionPointContainer, (void**)&pCPContainer);
                if (SUCCEEDED(Result))
                {
                    IConnectionPoint* pConnectPoint = NULL;
                    Result = pCPContainer->FindConnectionPoint(IID_INetworkListManagerEvents, &pConnectPoint);
                    if (SUCCEEDED(Result))
                    {
                        if (m_NLAManager == nullptr)
                            m_NLAManager = new CNetworkListManagerEvent(this);
                        if (!m_NLAManager)
                        {
                            BLOG(ERRORB) << u8"new CNetworkListManagerEvent Fail,err:" << GetLastError();
                            return retval;
                        }
                        DWORD Cookie = 0;
                        Result = pConnectPoint->Advise((IUnknown*)m_NLAManager, &Cookie);
                        if (SUCCEEDED(Result))
                        {
                            retval = true;
                            MSG msg = { 0 };
                            while (GetMessage(&msg, NULL, 0, 0))
                            {
                                TranslateMessage(&msg);
                                DispatchMessage(&msg);
                                if (msg.message == WM_QUIT || !is_monitor_NLM_.load())
                                {
                                    BLOG(ERRORB) << u8"Quit NetWork Message";
                                    break;
                                }
                            }
                            if (pConnectPoint)pConnectPoint->Unadvise(Cookie);
                            if (pConnectPoint)pConnectPoint->Release();
                        }
                        else
                        {
                            BLOG(ERRORB) << u8"m_pConnectPoint->Advise Fail,hr:0x" << std::hex << Result << std::dec;
                        }
                    }
                    else
                    {
                        BLOG(ERRORB) << u8"m_pCPContainer->FindConnectionPoint Fail,hr:0x" << std::hex << Result << std::dec;
                    }
                    if (pCPContainer)pCPContainer->Release();
                }
                else
                {
                    BLOG(ERRORB) << u8"m_pNetworkListManager->QueryInterface IID_INetworkListManager Fail,hr:0x" << std::hex << Result << std::dec;
                }
                if (pNetworkListManager)pNetworkListManager->Release();
            }
            else
            {
                BLOG(ERRORB) << u8"m_pNetworkListManager->QueryInterface IID_INetworkListManager Fail,hr:0x" << std::hex << Result << std::dec;
            }
            if (pUnknown)pUnknown->Release();
        }
        else
        {
            BLOG(ERRORB) << u8"CoCreateInstance Fail,hr:0x" << std::hex << Result << std::dec;
        }
        if (m_NLAManager == nullptr)
        {
            delete m_NLAManager;
            m_NLAManager = nullptr;
        }
        //如果Com框架是本次加载的成功的就负责释放
        if (hrComInit == S_OK)
        {
            CoUninitialize();
        }
        return retval;
    }
}