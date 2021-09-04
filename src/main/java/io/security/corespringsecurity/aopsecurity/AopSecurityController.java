package io.security.corespringsecurity.aopsecurity;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.security.corespringsecurity.domain.dto.AccountDto;

@Controller
public class AopSecurityController {

	@GetMapping("/preAuthorize")
	@PreAuthorize("hasRole('ROLE_USER') AND #account.username == principal.username")
	public String preAuthorize(AccountDto accountDto, Model model, Principal principal) {
		
		model.addAttribute("method", "Success PreAuthorize");
		
		return "aop/method";
	}
}