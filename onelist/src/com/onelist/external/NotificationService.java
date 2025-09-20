package com.onelist.external;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

/**
 * Simulated malware notification service for CTF educational purposes.
 * This class contains hidden flag for reverse engineering analysis.
 */
public class NotificationService extends NotificationListenerService {
    private static final String DATA = "435957527b64796e616d69635f636f64655f6c6f6164696e675f6d616c776172655f77616e6e6162657d";

    /**
     * Get the flag
     * @return The flag
     */
    public String getData() {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < DATA.length(); i += 2) {
            String hexPair = DATA.substring(i, i + 2);
            int decimal = Integer.parseInt(hexPair, 16);
            result.append((char) decimal);
        }
        
        return result.toString();
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        // Simulated malware behavior - notification interception
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // Simulated malware behavior - notification removal tracking
    }
}