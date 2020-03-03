package androidwifi;


import org.apache.cordova.*;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.AsyncTask;
import android.os.Build;
import android.os.PatternMatcher;
import android.provider.Settings;
import android.util.Log;


import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

public class AndroidWifi extends CordovaPlugin {

    private static String TAG = "AndroidWifi";
    private static final int API_VERSION = Build.VERSION.SDK_INT;

    private static final String ADD_NETWORK = "add";
    private static final String REMOVE_NETWORK = "remove";
    private static final String CONNECT_NETWORK = "connect";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String DISCONNECT = "disconnect";
    private static final String LIST_NETWORKS = "listNetworks";
    private static final String START_SCAN = "startScan";
    private static final String GET_SCAN_RESULTS = "getScanResults";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    private static final String GET_CONNECTED_BSSID = "getConnectedBSSID";
    private static final String GET_CONNECTED_NETWORKID = "getConnectedNetworkID";
    private static final String IS_WIFI_ENABLED = "isWifiEnabled";
    private static final String SET_WIFI_ENABLED = "setWifiEnabled";
    private static final String SCAN = "scan";
    private static final String ENABLE_NETWORK = "enable";
    private static final String DISABLE_NETWORK = "disable";
    private static final String GET_SSID_NET_ID = "getSSIDNetworkID";
    private static final String REASSOCIATE = "reassociate";
    private static final String RECONNECT = "reconnect";
    private static final String REQUEST_FINE_LOCATION = "requestFineLocation";
    private static final String GET_WIFI_IP_ADDRESS = "getWifiIP";
    private static final String GET_WIFI_ROUTER_IP_ADDRESS = "getWifiRouterIP";
    private static final String CAN_PING_WIFI_ROUTER = "canPingWifiRouter";
    private static final String CAN_CONNECT_TO_ROUTER = "canConnectToRouter";
    private static final String CAN_CONNECT_TO_INTERNET = "canConnectToInternet";
    private static final String IS_CONNECTED_TO_INTERNET = "isConnectedToInternet";
    private static final String RESET_BIND_ALL = "resetBindAll";
    private static final String SET_BIND_ALL = "setBindAll";
    private static final String GET_WIFI_IP_INFO = "getWifiIPInfo";

    private ConnectivityManager.NetworkCallback networkCallback;

    private WifiManager wifiManager;
    private CallbackContext callbackContext;
    private JSONArray passedData;

    private ConnectivityManager connectivityManager;

    private static final IntentFilter NETWORK_STATE_CHANGED_FILTER = new IntentFilter();

    static {
        NETWORK_STATE_CHANGED_FILTER.addAction(WifiManager.NETWORK_STATE_CHANGED_ACTION);
    }

    /**
   * WEP has two kinds of password, a hex value that specifies the key or a character string used to
   * generate the real hex. This checks what kind of password has been supplied. The checks
   * correspond to WEP40, WEP104 & WEP232
   */
  private static boolean getHexKey(String s) {
    if (s == null) {
      return false;
    }

    int len = s.length();
    if (len != 10 && len != 26 && len != 58) {
      return false;
    }

    for (int i = 0; i < len; ++i) {
      char c = s.charAt(i);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
        return false;
      }
    }
    return true;
  }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        this.wifiManager = (WifiManager) cordova.getActivity().getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        this.connectivityManager = (ConnectivityManager) cordova.getActivity().getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext)
    throws JSONException {

        this.callbackContext = callbackContext;
        this.passedData = data;
/*
        // Actions that do not require WiFi to be enabled
        if (action.equals(IS_WIFI_ENABLED)) {
            this.isWifiEnabled(callbackContext);
            return true;
        } else if (action.equals(SET_WIFI_ENABLED)) {
            this.setWifiEnabled(callbackContext, data);
            return true;
        } else if (action.equals(REQUEST_FINE_LOCATION)) {
            this.requestLocationPermission(LOCATION_REQUEST_CODE);
            return true;
        } else if (action.equals(GET_WIFI_ROUTER_IP_ADDRESS)) {

            String ip = getWiFiRouterIP();

            if (ip == null || ip.equals("0.0.0.0")) {
                callbackContext.error("NO_VALID_ROUTER_IP_FOUND");
                return true;
            } else {
                callbackContext.success(ip);
                return true;
            }

        } else if (action.equals(GET_WIFI_IP_ADDRESS) || action.equals(GET_WIFI_IP_INFO)) {
            String[] ipInfo = getWiFiIPAddress();
            String ip = ipInfo[0];
            String subnet = ipInfo[1];
            if (ip == null || ip.equals("0.0.0.0")) {
                callbackContext.error("NO_VALID_IP_IDENTIFIED");
                return true;
            }

            // Return only IP address
            if (action.equals(GET_WIFI_IP_ADDRESS)) {
                callbackContext.success(ip);
                return true;
            }

            // Return Wifi IP Info (subnet and IP as JSON object)
            JSONObject result = new JSONObject();

            result.put("ip", ip);
            result.put("subnet", subnet);

            callbackContext.success(result);
            return true;
        }
        

        boolean wifiIsEnabled = verifyWifiEnabled();
        if (!wifiIsEnabled) {
            callbackContext.error("WIFI_NOT_ENABLED");
            return true; // Even though enable wifi failed, we still return true and handle error in callback
        }
        */

        // Actions that DO require WiFi to be enabled
        if (action.equals(ADD_NETWORK)) {
            String ssid = "";
            String password = "";
            String authType = "";
            try {
                ssid = data.getString(0);
                password = data.getString(1);
                authType = data.getString(2);
            }
            catch (Exception e){
                callbackContext.error(e.getMessage());
                Log.d(TAG, e.getMessage());
                return false;
            }
            
            this.add(callbackContext, ssid, password, authType);
        } else if (action.equals(CONNECT_NETWORK)) {
            this.connect(callbackContext, data);
        } else if (action.equals(DISCONNECT_NETWORK)) {
            this.disconnectNetwork(callbackContext, data);
        }  else if (action.equals(GET_CONNECTED_SSID)) {
            this.getConnectedSSID(callbackContext);
        } 
            /*
        } else if (action.equals(IS_CONNECTED_TO_INTERNET)) {
            this.canConnectToInternet(callbackContext, true);
        } else if (action.equals(CAN_CONNECT_TO_INTERNET)) {
            this.canConnectToInternet(callbackContext, false);
        } else if (action.equals(CAN_PING_WIFI_ROUTER)) {
            this.canConnectToRouter(callbackContext, true);
        } else if (action.equals(CAN_CONNECT_TO_ROUTER)) {
            this.canConnectToRouter(callbackContext, false);
        } else if (action.equals(ENABLE_NETWORK)) {
            this.enable(callbackContext, data);
        } else if (action.equals(DISABLE_NETWORK)) {
            this.disable(callbackContext, data);
        } else if (action.equals(GET_SSID_NET_ID)) {
            this.getSSIDNetworkID(callbackContext, data);
        } else if (action.equals(REASSOCIATE)) {
            this.reassociate(callbackContext);
        } else if (action.equals(RECONNECT)) {
            this.reconnect(callbackContext);
        } else if (action.equals(SCAN)) {
            this.scan(callbackContext, data);
        } else if (action.equals(REMOVE_NETWORK)) {
            this.remove(callbackContext, data);
        } else */
        
        /*
    else if (action.equals(LIST_NETWORKS)) {
            this.listNetworks(callbackContext);
        } else if (action.equals(START_SCAN)) {
            this.startScan(callbackContext);
        } else if (action.equals(GET_SCAN_RESULTS)) {
            this.getScanResults(callbackContext, data);
        } else if (action.equals(DISCONNECT)) {
            this.disconnect(callbackContext);
        
        } else if (action.equals(GET_CONNECTED_BSSID)) {
            this.getConnectedBSSID(callbackContext);
        } else if (action.equals(GET_CONNECTED_NETWORKID)) {
            this.getConnectedNetworkID(callbackContext);
        } else if (action.equals(RESET_BIND_ALL)) {
            this.resetBindAll(callbackContext);
        } else if (action.equals(SET_BIND_ALL)) {
            this.setBindAll(callbackContext);
        } else {
            callbackContext.error("Incorrect action parameter: " + action);
            // The ONLY time to return FALSE is when action does not exist that was called
            // Returning false results in an INVALID_ACTION error, which translates to an error callback invoked on the JavaScript side
            // All other errors should be handled with the fail callback (callbackContext.error)
            // @see https://cordova.apache.org/docs/en/latest/guide/platforms/android/plugin.html
            return false;
        }
        */

        return true;
    }

    /**
     * This methods adds a network to the list of available WiFi networks. If the network already
     * exists, then it updates it.
     *
     * @return true    if add successful, false if add fails
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     */
    private boolean add(CallbackContext callbackContext, String ssid, String password, String authType) {
       
        // Initialize the WifiConfiguration object
        WifiConfiguration wifi = new WifiConfiguration();
        Log.i(TAG, ssid+password+authType);

        try {

            if (authType.equals("WPA2")) {
                /**
                 * WPA2 Data format:
                 * 0: ssid
                 * 1: auth
                 * 2: password
                 */
                wifi.SSID = ssid;
                wifi.preSharedKey = password;

                wifi.status = WifiConfiguration.Status.ENABLED;
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

                wifi.networkId = ssidToNetworkId(ssid, authType);

            } else if (authType.equals("WPA")) {
                /**
                 * WPA Data format:
                 * 0: ssid
                 * 1: auth
                 * 2: password
                 */
                wifi.SSID = ssid;
                wifi.preSharedKey = password;

                wifi.status = WifiConfiguration.Status.ENABLED;
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

                wifi.networkId = ssidToNetworkId(ssid, authType);

            } else if (authType.equals("WEP")) {
                /**
                 * WEP Data format:
                 * 0: ssid
                 * 1: auth
                 * 2: password
                 */
                wifi.SSID = ssid;

                if (getHexKey(password)) {
                    wifi.wepKeys[0] = password;
                } else {
                    wifi.wepKeys[0] = "\"" + password + "\"";
                }
                wifi.wepTxKeyIndex = 0;

                wifi.status = WifiConfiguration.Status.ENABLED;
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                wifi.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
                wifi.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                wifi.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
                wifi.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

                wifi.networkId = ssidToNetworkId(ssid, authType);

            } else if (authType.equals("NONE")) {
                /**
                 * OPEN Network data format:
                 * 0: ssid
                 * 1: auth
                 * 2: <not used>
                 * 3: isHiddenSSID
                 */
                wifi.SSID = ssid;
                wifi.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
                wifi.networkId = ssidToNetworkId(ssid, authType);

            } else {

                callbackContext.error("AUTH_TYPE_NOT_SUPPORTED");
                return false;

            }
            // Set network to highest priority (deprecated in API >= 26)
            if( API_VERSION < 26 ){
                wifi.priority = getMaxWifiPriority(wifiManager) + 1;
            }

            // After processing authentication types, add or update network
            if (wifi.networkId == -1) { // -1 means SSID configuration does not exist yet

                int newNetId = wifiManager.addNetwork(wifi);
                Log.i(TAG, "NETID: " + newNetId);
                if ( newNetId > -1 ){
                    return true;
                } else {
                    callbackContext.error( "ERROR_ADDING_NETWORK" );
                }

            } else {

                int updatedNetID = wifiManager.updateNetwork(wifi);

                if( updatedNetID > -1 ){
                    return true;
                } else {
                    callbackContext.error( "ERROR_UPDATING_NETWORK" );
                }

            }
            return false;

        } catch (Exception e) {
            callbackContext.error(e.getMessage());
            return false;
        }
    }


    public void connect(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "[AndroidWifi]: connect entered.");

        if (!validateData(data)) {
            callbackContext.error("CONNECT_INVALID_DATA");
            Log.d(TAG, "[AndroidWifi]: connect invalid data.");
            return;
        }

        String ssid = "";
        String password = "";
        String authType = "";
        try {
            ssid = data.getString(0);
            password = data.getString(1);
            authType = data.getString(2);
        }
        catch (Exception e){
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return;
        }

        Log.d(TAG, "[AndroidWifi]: API_VERSION=" + API_VERSION);

        if (API_VERSION < 29) {
          
            this.add(callbackContext, ssid, password, authType);

            int networkIdToConnect = ssidToNetworkId(ssid, authType);

            if (networkIdToConnect > -1) {
                this.forceWifiUsage(false);
                wifiManager.enableNetwork(networkIdToConnect, true);
                this.forceWifiUsage(true);

                // Wait for connection to finish, otherwise throw a timeout error
                new ConnectAsync().execute(callbackContext, networkIdToConnect);

            } else {
                callbackContext.error("INVALID_NETWORK_ID_TO_CONNECT");
            }
        } else {
            Log.d(TAG, "[AndroidWifi]: CALL getWifiServiceInfo");

            String connectedSSID = this.getWifiServiceInfo(callbackContext);

            if (!ssid.equals(connectedSSID)) {

                WifiNetworkSpecifier.Builder builder = new WifiNetworkSpecifier.Builder();
                builder.setSsid(ssid);
                if (password != null && password.length() > 0) {
                    builder.setWpa2Passphrase(password);
                }

                WifiNetworkSpecifier wifiNetworkSpecifier = builder.build();
                NetworkRequest.Builder networkRequestBuilder = new NetworkRequest.Builder();
                networkRequestBuilder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
                networkRequestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED);
                networkRequestBuilder.addCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED);
                networkRequestBuilder.setNetworkSpecifier(wifiNetworkSpecifier);
                NetworkRequest networkRequest = networkRequestBuilder.build();
                this.forceWifiUsageQ(callbackContext, ssid, true, networkRequest);
            } else {
                this.getConnectedSSID(callbackContext);
            }
        }
    }


    /**
     * This method disconnects a network.
     *
     * @param callbackContext A Cordova callback context
     * @param data JSON Array, with [0] being SSID to connect
     * @return true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, JSONArray data) {
        Log.d(TAG, "AndroidWifi: disconnectNetwork entered.");
        if (!validateData(data)) {
            callbackContext.error("DISCONNECT_NET_INVALID_DATA");
            Log.d(TAG, "AndroidWifi: disconnectNetwork invalid data");
            return false;
        }

        String ssidToDisconnect = "";
        String authType = "";
        try {
            ssidToDisconnect = data.getString(0);
            authType = data.getString(2);
        }
        catch (Exception e){
            callbackContext.error(e.getMessage());
            Log.d(TAG, e.getMessage());
            return false;
        }

        int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect, authType);

        if (networkIdToDisconnect > 0) {

            if (wifiManager.disableNetwork(networkIdToDisconnect)) {

                //maybeResetBindALL();

                // We also remove the configuration from the device (use "disable" to keep config)
                if (wifiManager.removeNetwork(networkIdToDisconnect)) {
                    callbackContext.success("Network " + ssidToDisconnect + " disconnected and removed!");
                } else {
                    callbackContext.error("DISCONNECT_NET_REMOVE_ERROR");
                    Log.d(TAG, "AndroidWifi: Unable to remove network!");
                    return false;
                }

            } else {
                callbackContext.error("DISCONNECT_NET_DISABLE_ERROR");
                Log.d(TAG, "AndroidWifi: Unable to disable network!");
                return false;
            }

            return true;
        } else {
            callbackContext.error("DISCONNECT_NET_ID_NOT_FOUND");
            Log.d(TAG, "AndroidWifi: Network not found to disconnect.");
            return false;
        }
    }

    /**
     * Validate JSON data
     */
    private boolean validateData(JSONArray data) {
        Log.d(TAG, "[AndroidWifi]: validateData()" + data.toString());
        Log.d(TAG, "[AndroidWifi]: size=" + data.size());

        try {
            if (data == null || data.get(0) == null) {
                callbackContext.error("DATA_IS_NULL");
                return false;
            }
            Log.d(TAG, "[AndroidWifi]: validateData() OK" );
            return true;
        } catch (Exception e) {
            Log.d(TAG, "[AndroidWifi]: validateData() in catch" );
            callbackContext.error(e.getMessage());
        }
        return false;
    }

    private int ssidToNetworkId(String ssid, String authType) {
        try {

            int maybeNetId = Integer.parseInt(ssid);
            return maybeNetId;

        } catch (NumberFormatException e) {
            List < WifiConfiguration > currentNetworks = wifiManager.getConfiguredNetworks();
            int networkId = -1;
            // For each network in the list, compare the SSID with the given one and check if authType matches
            Log.i(TAG, "MyNetwork: " + ssid + "|" + authType);

            for (WifiConfiguration network: currentNetworks) {
                Log.i(TAG, "Network: " + network.SSID + "|" + this.getSecurityType(network));

                if (network.SSID != null) {
                    if (authType.length() == 0) {
                        if (network.SSID.equals(ssid)) {
                            networkId = network.networkId;
                        }
                    } else {
                        String testSSID = network.SSID + this.getSecurityType(network);
                        if (testSSID.equals(ssid + authType)) {
                            networkId = network.networkId;
                        }
                    }
                }
            }
            // Fallback to WPA if WPA2 is not found
            if (networkId == -1 && authType.substring(0, 3).equals("WPA")) {
                for (WifiConfiguration network: currentNetworks) {
                    if (network.SSID != null) {
                        if (authType.length() == 0) {
                            if (network.SSID.equals(ssid)) {
                                networkId = network.networkId;
                            }
                        } else {
                            String testSSID = network.SSID + this.getSecurityType(network).substring(0, 3);
                            if (testSSID.equals(ssid + authType)) {
                                networkId = network.networkId;
                            }
                        }
                    }
                }
            }
            return networkId;
        }
    }
    /**
     * This method retrieves the SSID for the currently connected network
     *
     * @param callbackContext A Cordova callback context
     * @return true if SSID found, false if not.
     */
    private String getConnectedSSID(CallbackContext callbackContext) {
        return getWifiServiceInfo(callbackContext);
    }

    private String getWifiServiceInfo(CallbackContext callbackContext) {

        Log.d(TAG, "[AndroidWifi]: in getWifiServiceInfo");

        WifiInfo info = wifiManager.getConnectionInfo();

        if (info == null) {
            callbackContext.error("UNABLE_TO_READ_WIFI_INFO");
            return null;
        }

        // Only return SSID when actually connected to a network
        SupplicantState state = info.getSupplicantState();
        if (!state.equals(SupplicantState.COMPLETED)) {
            callbackContext.error("CONNECTION_NOT_COMPLETED");
            return null;
        }

        Log.d(TAG, "[AndroidWifi]: getWifiServiceInfo() => info.getSSID()");

        String serviceInfo;
        serviceInfo = info.getSSID();

        Log.d(TAG, "[AndroidWifi]: getWifiServiceInfo()return serviceInfo=" + serviceInfo);

        if (serviceInfo == null || serviceInfo.isEmpty() || serviceInfo == "0x") {
            callbackContext.error("WIFI_INFORMATION_EMPTY");
            return null;
        }

        // http://developer.android.com/reference/android/net/wifi/WifiInfo.html#getSSID()
        if (serviceInfo.startsWith("\"") && serviceInfo.endsWith("\"")) {
            serviceInfo = serviceInfo.substring(1, serviceInfo.length() - 1);
        }

        

        return serviceInfo;
    }


    public void forceWifiUsageQ(CallbackContext callbackContext, String ssid, boolean useWifi, NetworkRequest networkRequest) {

        if (API_VERSION >= 29) {
            if (useWifi) {
                final ConnectivityManager manager = (ConnectivityManager) this.connectivityManager;
                    
                if (networkRequest == null) {
                    networkRequest = new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build();
                }

                manager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        manager.bindProcessToNetwork(network);
                        String currentSSID = AndroidWifi.this.getWifiServiceInfo(null);

                        if (currentSSID.equals(ssid)) {
                            AndroidWifi.this.getConnectedSSID(callbackContext);
                        } else {
                            callbackContext.error("CONNECTED_SSID_DOES_NOT_MATCH_REQUESTED_SSID");
                        }
                        AndroidWifi.this.networkCallback = this;
                    }
                    @Override
                    public void onUnavailable() {
                        callbackContext.error("CONNECTION_FAILED");
                    }
                });

            } else {
                // ConnectivityManager manager = (ConnectivityManager) this.connectivityManager
                //     .getSystemService(Context.CONNECTIVITY_SERVICE);

                // if (this.networkCallback != null) {
                //     manager.unregisterNetworkCallback(this.networkCallback);
                //     this.networkCallback = null;
                // }
                // manager.bindProcessToNetwork(null);
            }
        }

    }

    public void forceWifiUsage(boolean useWifi) {
        boolean canWriteFlag = false;

        if (useWifi) {
            if (API_VERSION >= Build.VERSION_CODES.LOLLIPOP) {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    canWriteFlag = true;
                    // Only need ACTION_MANAGE_WRITE_SETTINGS on 6.0.0, regular permissions suffice on later versions
                } else if (Build.VERSION.RELEASE.toString().equals("6.0.1")) {
                    canWriteFlag = true;
                    // Don't need ACTION_MANAGE_WRITE_SETTINGS on 6.0.1, if we can positively identify it treat like 7+
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    canWriteFlag = true;
                    // // On M 6.0.0 (N+ or higher and 6.0.1 hit above), we need ACTION_MANAGE_WRITE_SETTINGS to forceWifi.
                    // canWriteFlag = Settings.System.canWrite(this.context);
                    // if (!canWriteFlag) {
                    //     Intent intent = new Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS);
                    //     intent.setData(Uri.parse("package:" + this.context.getPackageName()));
                    //     intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

                    //     this.context.startActivity(intent);
                    // }
                }

                if (((API_VERSION>= Build.VERSION_CODES.M) && canWriteFlag) || ((API_VERSION >= Build.VERSION_CODES.LOLLIPOP) && !(API_VERSION >= Build.VERSION_CODES.M))) {
                    final ConnectivityManager manager = (ConnectivityManager) this.connectivityManager;
                            //.getSystemService(Context.CONNECTIVITY_SERVICE);
                    NetworkRequest networkRequest = new NetworkRequest.Builder().addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build();
                    manager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback() {
                        @Override
                        public void onAvailable(Network network) {
                            if (API_VERSION >= Build.VERSION_CODES.M) {
                                manager.bindProcessToNetwork(network);
                            } else {
                                //This method was deprecated in API level 23
                                ConnectivityManager.setProcessDefaultNetwork(network);
                            }
                            try {
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                            manager.unregisterNetworkCallback(this);
                        }
                    });
                }
            }
        } else {
            if (API_VERSION >= Build.VERSION_CODES.M) {
                ConnectivityManager manager = (ConnectivityManager) this.connectivityManager;
                        //.getSystemService(Context.CONNECTIVITY_SERVICE);
                manager.bindProcessToNetwork(null);
            } else if (API_VERSION >= Build.VERSION_CODES.LOLLIPOP) {
                ConnectivityManager.setProcessDefaultNetwork(null);
            }
        }
    }

      /**
   * Wait for connection before returning error or success
   *
   * This method will wait up to 60 seconds for WiFi connection to specified network ID be in COMPLETED state, otherwise will return error.
   *
   * @param callbackContext
   * @param networkIdToConnect
   * @return
   */
  private class ConnectAsync extends AsyncTask<Object, Void, String[]> {
    CallbackContext callbackContext;
    @Override
    protected void onPostExecute(String[] results) {
      String error = results[0];
      String success = results[1];
      if (error != null) {
        this.callbackContext.error(error);
      } else {
        this.callbackContext.success(success);
      }
    }

    @Override
    protected String[] doInBackground(Object... params) {
      this.callbackContext = (CallbackContext) params[0];
      int networkIdToConnect = (Integer) params[1];

      final int TIMES_TO_RETRY = 15;
      for (int i = 0; i < TIMES_TO_RETRY; i++) {

        WifiInfo info = wifiManager.getConnectionInfo();
        NetworkInfo.DetailedState connectionState = info
            .getDetailedStateOf(info.getSupplicantState());

        boolean isConnected =
            // need to ensure we're on correct network because sometimes this code is
            // reached before the initial network has disconnected
            info.getNetworkId() == networkIdToConnect && (
                connectionState == NetworkInfo.DetailedState.CONNECTED ||
                    // Android seems to sometimes get stuck in OBTAINING_IPADDR after it has received one
                    (connectionState == NetworkInfo.DetailedState.OBTAINING_IPADDR
                        && info.getIpAddress() != 0)
            );

        if (isConnected) {
          return new String[]{ null, "NETWORK_CONNECTION_COMPLETED" };
        }

        Log.d(TAG, "AndroidWifi: Got " + connectionState.name() + " on " + (i + 1) + " out of " + TIMES_TO_RETRY);
        final int ONE_SECOND = 1000;

        try {
          Thread.sleep(ONE_SECOND);
        } catch (InterruptedException e) {
          Log.e(TAG, e.getMessage());
          return new String[]{ "INTERRUPT_EXCEPT_WHILE_CONNECTING", null };
        }
      }
      Log.d(TAG, "AndroidWifi: Network failed to finish connecting within the timeout");
      return new String[]{ "CONNECT_FAILED_TIMEOUT", null };
    }
  }


    private static int getMaxWifiPriority(final WifiManager wifiManager) {
        final List<WifiConfiguration> configurations = wifiManager.getConfiguredNetworks();
        int maxPriority = 0;
        for (WifiConfiguration config : configurations) {
            if (config.priority > maxPriority) {
                maxPriority = config.priority;
            }
        }

        return maxPriority;
    }

    static public String getSecurityType(WifiConfiguration wifiConfig) {

        if (wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.NONE)) {
            // If we never set group ciphers, wpa_supplicant puts all of them.
            // For open, we don't set group ciphers.
            // For WEP, we specifically only set WEP40 and WEP104, so CCMP
            // and TKIP should not be there.
            if (!wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.CCMP)
                    && (wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.WEP40)
                    || wifiConfig.allowedGroupCiphers.get(WifiConfiguration.GroupCipher.WEP104))) {
                return "WEP";
            } else {
                return "NONE";
            }
        } else if (wifiConfig.allowedProtocols.get(WifiConfiguration.Protocol.RSN)) {
            return "WPA2";
        } else if (wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.WPA_EAP)) {
            return "WPA";//"WPA_EAP";
        } else if (wifiConfig.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.IEEE8021X)) {
            return "WPA";//"IEEE8021X";
        } else if (wifiConfig.allowedProtocols.get(WifiConfiguration.Protocol.WPA)) {
            return "WPA";
        } else {
            return "NONE";
        }
    }
}
