package org.sid.productservice.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class ProductRESTAPI {
    @GetMapping("/products")
    @PreAuthorize("hasAuthority('ADMIN')")
    public Map<String,Object> product(Authentication authentication){
        return Map.of("name","PC DELL","price",123,"username",authentication.getName(),"scope",authentication.getAuthorities());
    }
}
