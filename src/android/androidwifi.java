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

import java.util.ArrayList;
import java.util.List;

public enum SuppState {
    /**
         * This state indicates that client is not associated, but is likely to
         * start looking for an access point. This state is entered when a
         * connection is lost.
         */
        DISCONNECTED,
        /**
         * Interface is disabled
         * <p/>
         * This state is entered if the network interface is disabled.
         * wpa_supplicant refuses any new operations that would
         * use the radio until the interface has been enabled.
         */
        INTERFACE_DISABLED,
        /**
         * Inactive state (wpa_supplicant disabled).
         * <p/>
         * This state is entered if there are no enabled networks in the
         * configuration. wpa_supplicant is not trying to associate with a new
         * network and external interaction (e.g., ctrl_iface call to add or
         * enable a network) is needed to start association.
         */
        INACTIVE,
        /**
         * Scanning for a network.
         * <p/>
         * This state is entered when wpa_supplicant starts scanning for a
         * network.
         */
        SCANNING,
        /**
         * Trying to authenticate with a BSS/SSID
         * <p/>
         * This state is entered when wpa_supplicant has found a suitable BSS
         * to authenticate with and the driver is configured to try to
         * authenticate with this BSS.
         */
        AUTHENTICATING,
        /**
         * Trying to associate with a BSS/SSID.
         * <p/>
         * This state is entered when wpa_supplicant has found a suitable BSS
         * to associate with and the driver is configured to try to associate
         * with this BSS in ap_scan=1 mode. When using ap_scan=2 mode, this
         * state is entered when the driver is configured to try to associate
         * with a network using the configured SSID and security policy.
         */
        ASSOCIATING,
        /**
         * Association completed.
         * <p/>
         * This state is entered when the driver reports that association has
         * been successfully completed with an AP. If IEEE 802.1X is used
         * (with or without WPA/WPA2), wpa_supplicant remains in this state
         * until the IEEE 802.1X/EAPOL authentication has been completed.
         */
        ASSOCIATED,
        /**
         * WPA 4-Way Key Handshake in progress.
         * <p/>
         * This state is entered when WPA/WPA2 4-Way Handshake is started. In
         * case of WPA-PSK, this happens when receiving the first EAPOL-Key
         * frame after association. In case of WPA-EAP, this state is entered
         * when the IEEE 802.1X/EAPOL authentication has been completed.
         */
        FOUR_WAY_HANDSHAKE,
        /**
         * WPA Group Key Handshake in progress.
         * <p/>
         * This state is entered when 4-Way Key Handshake has been completed
         * (i.e., when the supplicant sends out message 4/4) and when Group
         * Key rekeying is started by the AP (i.e., when supplicant receives
         * message 1/2).
         */
        GROUP_HANDSHAKE,
        /**
         * All authentication completed.
         * <p/>
         * This state is entered when the full authentication process is
         * completed. In case of WPA2, this happens when the 4-Way Handshake is
         * successfully completed. With WPA, this state is entered after the
         * Group Key Handshake; with IEEE 802.1X (non-WPA) connection is
         * completed after dynamic keys are received (or if not used, after
         * the EAP authentication has been completed). With static WEP keys and
         * plaintext connections, this state is entered when an association
         * has been completed.
         * <p/>
         * This state indicates that the supplicant has completed its
         * processing for the association phase and that data connection is
         * fully configured. Note, however, that there may not be any IP
         * address associated with the connection yet. Typically, a DHCP
         * request needs to be sent at this point to obtain an address.
         */
        COMPLETED,
        /**
         * An Android-added state that is reported when a client issues an
         * explicit DISCONNECT command. In such a case, the supplicant is
         * not only dissociated from the current access point (as for the
         * DISCONNECTED state above), but it also does not attempt to connect
         * to any access point until a RECONNECT or REASSOCIATE command
         * is issued by the client.
         */
        DORMANT,
        /**
         * No connection to wpa_supplicant.
         * <p/>
         * This is an additional pseudo-state to handle the case where
         * wpa_supplicant is not running and/or we have not been able
         * to establish a connection to it.
         */
        UNINITIALIZED,
        /**
         * A pseudo-state that should normally never be seen.
         */
        INVALID;

    }

public class AndroidWifi extends CordovaPlugin {

    private static String TAG = "AndroidWifi";
    private static final int API_VERSION = Build.VERSION.SDK_INT;

    private static final String ADD_NETWORK = "add";
    private static final String CONNECT_NETWORK = "connect";
    private static final String DISCONNECT_NETWORK = "disconnectNetwork";
    private static final String GET_CONNECTED_SSID = "getConnectedSSID";
    
    private ConnectivityManager.NetworkCallback networkCallback = null;
    private ConnectivityManager connectivityManager;
    private WifiManager wifiManager;
    private CallbackContext callbackContext;

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

        String ssid = "";
        String password = "";
        String authType = "";

        if (action.equals(ADD_NETWORK) ||
            action.equals(CONNECT_NETWORK) ||
            action.equals(DISCONNECT_NETWORK)) {

            if (!validateData(data)) {
                callbackContext.error("CONNECT_INVALID_DATA");
                Log.d(TAG, "AndroidWifi: " + action + " invalid data.");
                return false;
            }

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
        }

        // Actions that DO require WiFi to be enabled
        if (action.equals(ADD_NETWORK)) {
            this.add(callbackContext, ssid, password, authType);
        } else if (action.equals(CONNECT_NETWORK)) {
            this.connect(callbackContext, ssid, password, authType);
        } else if (action.equals(DISCONNECT_NETWORK)) {
            this.disconnectNetwork(callbackContext, ssid, password, authType);
        }  else if (action.equals(GET_CONNECTED_SSID)) {
            this.getConnectedSSID(callbackContext);
        } 

        return true;
    }

   


    public void connect(CallbackContext callbackContext, String ssid, String password, String authType) {
        Log.d(TAG, "AndroidWifi: connect entered.");

        Log.d(TAG, "AndroidWifi: API_VERSION=" + API_VERSION);

        if (API_VERSION >= 29) {

            String connectedSSID = this.getConnectedSSID(callbackContext);

            if (!ssid.equals(connectedSSID)) 
            {
                LOG.d(TAG, "!ssid.equals(connectedSSID)" + ssid + '|' + connectedSSID);

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

        } else {

            callbackContext.error("API_VERSION_BELOW_29_NOT_SUPPORTED");
        

        }
    }


    /**
     * This method disconnects a network.
     *
     * @param callbackContext A Cordova callback context
     * @param data JSON Array, with [0] being SSID to connect
     * @return true if network disconnected, false if failed
     */
    private boolean disconnectNetwork(CallbackContext callbackContext, String ssidToDisconnect, String password, String authType) {
        
        Log.d(TAG, "AndroidWifi: disconnectNetwork entered.");
        
        if (API_VERSION >= 29) {

            maybeResetBindALL();
            callbackContext.success("Network " + ssidToDisconnect + " unregisterNetworkCallback!");
            return true;

        }
        else
        {
            int networkIdToDisconnect = get_connectionInfo_networkId(callbackContext);

        //int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect, authType);

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
            } else { //networkIdToDisconnect == -1
                
                callbackContext.error("DISCONNECT_NET_ID_NOT_FOUND");
                Log.d(TAG, "AndroidWifi: Network not found to disconnect.");
            }
        }
        return false;
    }

    /**
     * Validate JSON data
     */
    private boolean validateData(JSONArray data) {
        Log.d(TAG, "AndroidWifi: validateData()" + data.toString());
        //Log.d(TAG, "AndroidWifi: size=" + data.size());

        try {
            if (data == null || data.get(0) == null) {
                callbackContext.error("DATA_IS_NULL");
                return false;
            }
            Log.d(TAG, "AndroidWifi: validateData() OK" );
            return true;
        } catch (Exception e) {
            Log.d(TAG, "AndroidWifi: validateData() in catch" );
            callbackContext.error(e.getMessage());
        }
        return false;
    }

    
    /**
     * This method retrieves the SSID for the currently connected network
     *
     * @param callbackContext A Cordova callback context
     * @return true if SSID found, false if not.
     */
    private String getConnectedSSID(CallbackContext callbackContext) {
    
        Log.d(TAG, "getConnectedSSID");

        // if (networkCallback == null){
        //     callbackContext.error("CONNECTION_NOT_COMPLETED");
        //     return null;
        // }

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

        String ssid = info.getSSID();

        Log.d(TAG, "ssid=" + ssid);

        if (ssid == null || ssid.isEmpty() || ssid == "0x") {
            callbackContext.error("WIFI_INFORMATION_EMPTY");
            return null;
        }

        // http://developer.android.com/reference/android/net/wifi/WifiInfo.html#getSSID()
        if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
            ssid = ssid.substring(1, ssid.length() - 1);
        }

        Log.d(TAG, "stripped ssid=" + ssid);

        return ssid;
    }

      /**
     * This method takes a given String, searches the current list of configured WiFi networks, and
     * returns the networkId for the network if the SSID matches. If not, it returns -1.
     */
    private int ssidToNetworkId(String ssid, String authType) {

        String ssidComp = "\"" + ssid + "\"";

        if (ssid.startsWith("\"")) {
            ssidComp = ssid;
        }

        Log.i(TAG, "MyNetwork: " + ssidComp + "|" + authType);
        
        try {

            int maybeNetId = Integer.parseInt(ssid);
            return maybeNetId;

        } catch (NumberFormatException e) {
    
            Log.i(TAG, "catch (NumberFormatException e):" + e);
            
        }

        int networkId = -1;
            
        List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();

        if (currentNetworks != null){
            Log.i(TAG, "Number of networks: " + currentNetworks.size());
        }
        else {
            Log.i(TAG, "wifiManager.getConfiguredNetworks() returned null");
        }
        
        // For each network in the list, compare the SSID with the given one
        for (WifiConfiguration network : currentNetworks) {
            Log.i(TAG, "network: " + network.SSID + "|" + networkId);
            if (network.SSID != null && network.SSID.equals(ssidComp)) {
                networkId = network.networkId;
                Log.i(TAG, "networkId: " + networkId);
                return networkId;
            }
        }

        Log.i(TAG, "networkId: " + networkId);
        return networkId;
    }
    /*
    private int ssidToNetworkId(String ssid, String authType) {
        
        try {

            int maybeNetId = Integer.parseInt(ssid);
            return maybeNetId;

        } catch (NumberFormatException e) {  
            List<WifiConfiguration> currentNetworks = wifiManager.getConfiguredNetworks();
            
            // For each network in the list, compare the SSID with the given one and check if authType matches
            Log.i(TAG, "MyNetwork: " + ssid + "|" + authType);

            for (WifiConfiguration network : currentNetworks) {
                Log.i(TAG, "Network: " + network.SSID + "|" + this.getSecurityType(network));

                if (network.SSID != null) {
                    if (authType.length() == 0) {
                        if(network.SSID.equals(ssid)) {
                            networkId = network.networkId;
                        }
                    } else {
                        String testSSID = network.SSID + this.getSecurityType(network);
                        if(testSSID.equals(ssid + authType)) {
                            networkId = network.networkId;
                        }
                    }
                }
            }
            // Fallback to WPA if WPA2 is not found
            if (networkId == -1 && authType.substring(0,3).equals("WPA")) {
                for (WifiConfiguration network : currentNetworks) {
                    if (network.SSID != null) {
                        if (authType.length() == 0) {
                            if(network.SSID.equals(ssid)) {
                                networkId = network.networkId;
                            }
                        } else {
                            String testSSID = network.SSID + this.getSecurityType(network).substring(0,3);
                            if(testSSID.equals(ssid + authType)) {
                                networkId = network.networkId;
                            }
                        }
                    }
                }
            }
        }
        Log.i(TAG, "networkId: " + networkId);
        return networkId;
    }
    */
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
                        String currentSSID = AndroidWifi.this.getConnectedSSID(callbackContext);

                        Log.i(TAG, "currentSSID: " + currentSSID);
                        Log.i(TAG, "ssid: " + ssid);

                        if (currentSSID == "<unknown ssid>"){
                            callbackContext.success("connected to " + currentSSID);
                        }
                        else {
                            if (currentSSID.equals(ssid)) {
                                callbackContext.success("connected to " + currentSSID);
                            } else {
                                callbackContext.error("CONNECTED_SSID_DOES_NOT_MATCH_REQUESTED_SSID");
                            }
                        }
                        
                        AndroidWifi.this.networkCallback = this;
                    }
                    @Override
                    public void onUnavailable() {
                        //base.OnUnavailable();

                        //NetworkUnavailable?.Invoke();
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

    /**
   * Maybe reset bind all after disconnect/disable
   *
   * This method unregisters the network changed receiver, as well as setting null for
   * bindProcessToNetwork or setProcessDefaultNetwork to prevent future sockets from application
   * being routed through Wifi.
   */
    private void maybeResetBindALL(){

        Log.d(TAG, "maybeResetBindALL");

        if ( API_VERSION >= 29 ) {
            connectivityManager.bindProcessToNetwork(null);
        
            try {
            // Same behavior as releaseNetworkRequest
                connectivityManager.unregisterNetworkCallback(networkCallback); // Added in API 21
                networkCallback = null;
            } catch (Exception e) {}
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



    private int get_connectionInfo_networkId(CallbackContext callbackContext) {

        Log.i(TAG, "get_connectionInfo_networkId enter");
        
        WifiInfo info = wifiManager.getConnectionInfo();

        if (info == null) {
            callbackContext.error("UNABLE_TO_READ_WIFI_INFO");
            return -1;
        }

        // Only return SSID when actually connected to a network
        SupplicantState state = info.getSupplicantState();
        if (!state.equals(SupplicantState.COMPLETED)) {
            switch (state){
                case SuppState.DISCONNECTED:  callbackContext.error("CONNECTION_NOT_COMPLETED|DISCONNECTED");return -1;
                case SuppState.INTERFACE_DISABLED:  callbackContext.error("CONNECTION_NOT_COMPLETED|INTERFACE_DISABLED");return -1;
                case SuppState.INACTIVE:  callbackContext.error("CONNECTION_NOT_COMPLETED|INACTIVE");return -1;
                case SuppState.SCANNING:  callbackContext.error("CONNECTION_NOT_COMPLETED|SCANNING");return -1;
                case SuppState.AUTHENTICATING:  callbackContext.error("CONNECTION_NOT_COMPLETED|AUTHENTICATING");return -1;
                case SuppState.ASSOCIATING:  callbackContext.error("CONNECTION_NOT_COMPLETED|ASSOCIATING");return -1;
                case SuppState.ASSOCIATED:  callbackContext.error("CONNECTION_NOT_COMPLETED|ASSOCIATED");return -1;
                case SuppState.FOUR_WAY_HANDSHAKE:  callbackContext.error("CONNECTION_NOT_COMPLETED|FOUR_WAY_HANDSHAKE");return -1;
                case SuppState.GROUP_HANDSHAKE:  callbackContext.error("CONNECTION_NOT_COMPLETED|GROUP_HANDSHAKE");return -1;
                case SuppState.DORMANT:  callbackContext.error("CONNECTION_NOT_COMPLETED|DORMANT");return -1;
                case SuppState.UNINITIALIZED:  callbackContext.error("CONNECTION_NOT_COMPLETED|UNINITIALIZED");return -1;
                case SuppState.INVALID:  callbackContext.error("CONNECTION_NOT_COMPLETED|INVALID");return -1;
            }
            callbackContext.error("CONNECTION_NOT_COMPLETED");
            return -1;
        }

        Log.i(TAG, "get_connectionInfo_networkId networkId: " + info.getNetworkId());

        return info.getNetworkId();
    }

    /*************************************************
     *  
     *    API_VERSION < 29
     * 
     *************************************************/

    /**
     * Figure out what the highest priority network in the network list is and return that priority
     */
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

     /**
     * This methods adds a network to the list of available WiFi networks. If the network already
     * exists, then it updates it.
     *
     * @return true    if add successful, false if add fails
     * @params callbackContext     A Cordova callback context.
     * @params data                JSON Array with [0] == SSID, [1] == password
     */
    private boolean add(CallbackContext callbackContext, String ssid, String password, String authType) {
       
        Log.d(TAG, "AndroidWifi add(" + ssid + "|" + authType + ")" );

        // Initialize the WifiConfiguration object
        WifiConfiguration wifi = new WifiConfiguration();

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

}
