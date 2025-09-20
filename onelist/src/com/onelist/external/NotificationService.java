package com.onelist.external;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

/**
 * Simulated malware notification service for CTF educational purposes.
 * This class contains hidden flag for reverse engineering analysis.
 */
public class NotificationService extends NotificationListenerService {
    private static final String FLAG = "CYWR{dynamic_code_loading_malware_wannabe}";

    /**
     * Get the flag
     * @return The flag
     */
    public String getFlag() {
        return FLAG;
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