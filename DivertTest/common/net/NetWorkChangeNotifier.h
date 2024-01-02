#pragma once
#include <shared_mutex>
namespace net {
    typedef struct _MIB_IPINTERFACE_ROW {
        //
        // Key Structure;
        //
        ADDRESS_FAMILY Family;
        NET_LUID InterfaceLuid;
        NET_IFINDEX InterfaceIndex;

        //
        // Read-Write fields.
        //

        //
        // Fields currently not exposed.
        //
        ULONG MaxReassemblySize;
        ULONG64 InterfaceIdentifier;
        ULONG MinRouterAdvertisementInterval;
        ULONG MaxRouterAdvertisementInterval;

        //
        // Fileds currently exposed.
        //
        BOOLEAN AdvertisingEnabled;
        BOOLEAN ForwardingEnabled;
        BOOLEAN WeakHostSend;
        BOOLEAN WeakHostReceive;
        BOOLEAN UseAutomaticMetric;
        BOOLEAN UseNeighborUnreachabilityDetection;
        BOOLEAN ManagedAddressConfigurationSupported;
        BOOLEAN OtherStatefulConfigurationSupported;
        BOOLEAN AdvertiseDefaultRoute;

        NL_ROUTER_DISCOVERY_BEHAVIOR RouterDiscoveryBehavior;
        ULONG DadTransmits;         // DupAddrDetectTransmits in RFC 2462.
        ULONG BaseReachableTime;
        ULONG RetransmitTime;
        ULONG PathMtuDiscoveryTimeout; // Path MTU discovery timeout (in ms).

        NL_LINK_LOCAL_ADDRESS_BEHAVIOR LinkLocalAddressBehavior;
        ULONG LinkLocalAddressTimeout; // In ms.
        ULONG ZoneIndices[ScopeLevelCount]; // Zone part of a SCOPE_ID.
        ULONG SitePrefixLength;
        ULONG Metric;
        ULONG NlMtu;

        //
        // Read Only fields.
        //
        BOOLEAN Connected;
        BOOLEAN SupportsWakeUpPatterns;
        BOOLEAN SupportsNeighborDiscovery;
        BOOLEAN SupportsRouterDiscovery;

        ULONG ReachableTime;

        NL_INTERFACE_OFFLOAD_ROD TransmitOffload;
        NL_INTERFACE_OFFLOAD_ROD ReceiveOffload;

        //
        // Disables using default route on the interface. This flag
        // can be used by VPN clients to restrict Split tunnelling.
        //
        BOOLEAN DisableDefaultRoutes;
    } MIB_IPINTERFACE_ROW, * PMIB_IPINTERFACE_ROW;
    class NetworkChangeMonitor;
    class CNetworkListManagerEvent : public INetworkListManagerEvents
    {
    public:
        CNetworkListManagerEvent(NetworkChangeMonitor* network_change_obj) : m_ref(1), network_change_monitor_(network_change_obj)
        {

        }

        ~CNetworkListManagerEvent()
        {

        }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject)
        {
            HRESULT Result = S_OK;
            if (IsEqualIID(riid, IID_IUnknown))
            {
                *ppvObject = (IUnknown*)this;
            }
            else if (IsEqualIID(riid, IID_INetworkListManagerEvents))
            {
                *ppvObject = (INetworkListManagerEvents*)this;
            }
            else
            {
                Result = E_NOINTERFACE;
            }

            return Result;
        }

        ULONG STDMETHODCALLTYPE AddRef()
        {
            return (ULONG)InterlockedIncrement(&m_ref);
        }

        ULONG STDMETHODCALLTYPE Release()
        {
            LONG Result = InterlockedDecrement(&m_ref);
            if (Result == 0)
                delete this;
            return (ULONG)Result;
        }

        virtual HRESULT STDMETHODCALLTYPE ConnectivityChanged(/* [in] */ NLM_CONNECTIVITY newConnectivity);
    private:
        NetworkChangeMonitor* network_change_monitor_;
        LONG m_ref;
    };

    class INetworkChangeCallback {
    public:
        enum NetworkChangeEventType
        {
            NETWORK_CHANGE_EVENT_NONE = 0,
            NETWORK_CHANGE_EVENT_INTERFACE_CHANGE = 1,
            NETWORK_CHANGE_EVENT_NLM = 2,

        };
        struct NetworkChangeInfo {
            NetworkChangeEventType event_type;
            bool is_connected;
            NL_NETWORK_CONNECTIVITY_LEVEL_HINT current_connect_level;

        };
    public:
        virtual ~INetworkChangeCallback() {};
        virtual void  NetWorkChange() = 0;
    };

    class NetworkChangeMonitor
    {
    public:
        NetworkChangeMonitor();
        ~NetworkChangeMonitor();
        void Initialize();
        void UnInitialize();
        bool RegisterNetworkChangeCallback(INetworkChangeCallback* callback);
        void UnRegisterNetworkChangeCallback(INetworkChangeCallback* callback);

        static unsigned __stdcall MonitorNetworkChangeThread(void* param);
        void ConnectivityChanged(/* [in] */ NLM_CONNECTIVITY newConnectivity);

        static VOID __stdcall InterfaceChangeCallback(
            _In_ PVOID CallerContext,
            _In_ PMIB_IPINTERFACE_ROW Row OPTIONAL,
            _In_ MIB_NOTIFICATION_TYPE NotificationType
        );
        static unsigned __stdcall MonitorInterfaceChangeThread(void* param);
    private:
        bool StartNLMInterfaceMonitor();
        bool StartInterfaceChangeMonitor();
        bool StopNLMInterfaceMonitor();
        bool StopInterfaceChangeMonitor();
        unsigned MonitorNetworkChangeRunner();
        unsigned MonitorInterfaceChangeRunner();
        VOID InterfaceChangeCallbackImpl(_In_ PMIB_IPINTERFACE_ROW Row OPTIONAL, _In_ MIB_NOTIFICATION_TYPE NotificationTyp);
    private:
        std::shared_mutex callback_list_mutex_;
        std::vector<INetworkChangeCallback*> callback_list_;

        std::atomic_bool is_monitor_NLM_;
        std::atomic_bool is_monitor_interface_change_;


        HANDLE netchange_monitor_nlm_thread_handle_ = nullptr;
        CNetworkListManagerEvent* m_NLAManager = nullptr;


        HANDLE netchange_monitor_ipchange_thread_handle_ = nullptr;
        HANDLE interfacechange_handle_ = nullptr;

        HANDLE interfacechange_shutdown_event_ = nullptr;

    };
}