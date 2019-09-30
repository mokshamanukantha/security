package com.unipoint.security.util;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthBuilder {
    private String firebaseConfig;
    private String firebaseDb;
    private String authPath;
    private String tokenHeader;
}
