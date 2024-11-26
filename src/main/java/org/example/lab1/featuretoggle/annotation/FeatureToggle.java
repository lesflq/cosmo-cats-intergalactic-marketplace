package org.example.lab1.featuretoggle.annotation;

import org.example.lab1.featuretoggle.FeatureToggles;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface FeatureToggle {
    FeatureToggles value();
}