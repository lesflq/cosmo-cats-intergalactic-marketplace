package org.example.lab1.featuretoggle;

import lombok.Getter;

@Getter
public enum FeatureToggles {
    CUSTOMER_GREETING("customer-greeting"),
    COSMO_CATS("cosmoCats");
    private final String featureName;
    FeatureToggles(String featureName) {
        this.featureName = featureName;
    }
}