package br.com.alura.forum.controller;

import br.com.alura.forum.config.security.TokenService;
import br.com.alura.forum.controller.dto.TokenDto;
import br.com.alura.forum.controller.form.LoginForm;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
@Profile(value = {"prod", "test"})
public class AutenticacaoController {

    private final Counter authUserSuccess;
    private final Counter authUserError;

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private TokenService tokenService;

    public AutenticacaoController(MeterRegistry registry) {
        /**
         * custom metrics
         */
        this.authUserSuccess = Counter
                .builder("auth_user_success")
                .description("usuarios autenticados")
                .register(registry);

        this.authUserError = Counter
                .builder("auth_user_error")
                .description("erros de login")
                .register(registry);
    }

    @PostMapping
    public ResponseEntity<TokenDto> autenticar(@RequestBody @Valid LoginForm form) {
        UsernamePasswordAuthenticationToken dadosLogin = form.converter();

        try {
            Authentication authentication = authManager.authenticate(dadosLogin);
            String token = tokenService.gerarToken(authentication);

            authUserSuccess.increment();

            return ResponseEntity.ok(new TokenDto(token, "Bearer"));

        } catch (AuthenticationException e) {

            authUserError.increment();

            return ResponseEntity.badRequest().build();
        }


    }
}
