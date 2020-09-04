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
            int networkIdToDisconnect = getConnectedNetworkId(callbackContext);

        //int networkIdToDisconnect = ssidToNetworkId(ssidToDisconnect, authType);

            if (networkIdToDisconnect > 0) {

//             disableNetwork sometimes doesn't work for API_VERSION < 29
//             workaround: disconnect instead (removeNetwork might nog work)

                boolean disabled = wifiManager.disableNetwork(networkIdToDisconnect);
                boolean disconnected = disabled;
                boolean removed = false;

                if (!disabled)
                {
                    removed = wifiManager.removeNetwork(networkIdToDisconnect);
                    Log.d(TAG, "AndroidWifi: Unable to disableNetwork networkId=" + networkIdToDisconnect);

                    disconnected = wifiManager.disconnect();

                    if (!disconnected){
                        Log.d(TAG, "AndroidWifi: Unable to disconnect() networkId=" + networkIdToDisconnect);
                    }

                }

                if (disconnected || disabled) {

                    //maybeResetBindALL();
                    if (!removed){
                        removed = wifiManager.removeNetwork(networkIdToDisconnect);
                    }

                    // We also remove the configuration from the device (use "disable" to keep config)
                    if (disconnected && removed)
                    {
                        callbackContext.success("Network " + ssidToDisconnect + " disconnected and removed!");
                    }
                    else if (disconnected)
                    {
                        callbackContext.success("Network " + ssidToDisconnect + " disconnected!");
                    }
                    else
                    {
                        callbackContext.error("DISCONNECT_NET_REMOVE_ERROR");
                        Log.d(TAG, "AndroidWifi: Unable to remove network!");
                        return false;
                    }
                } else {

                    callbackContext.error("DISCONNECT_NET_DISABLE_ERROR");
                    Log.d(TAG, "AndroidWifi: Unable to disable network! networkIdToDisconnect=" + networkIdToDisconnect);
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

        if (ssid == null || ssid.isEmpty() || ssid == "0x" ) {
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



    private int getConnectedNetworkId(CallbackContext callbackContext) {

        WifiInfo info = wifiManager.getConnectionInfo();

        if (info == null) {
            callbackContext.error("UNABLE_TO_READ_WIFI_INFO");
            return -1;
        }

        // Only return SSID when actually connected to a network
        SupplicantState state = info.getSupplicantState();
        if (!state.equals(SupplicantState.COMPLETED)) {
            getConnectedSSID(callbackContext);
            return -1;
        }

        Log.i(TAG, "networkId: " + info.getNetworkId());

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
