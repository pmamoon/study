package io.security.corespringsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.service.SecurityResourceService;

@Configuration
public class AppConfig {

	@Bean
	public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
		SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
		return securityResourceService;
	}
	
}
