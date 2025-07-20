package com.prueba.login.controller;

import com.prueba.login.config.JwtAuthenticationFilter;
import com.prueba.login.dto.JwtRequest;
import com.prueba.login.dto.JwtResponse;
import com.prueba.login.dto.UsuarioResponseDTO;
import com.prueba.login.entity.Usuario;
import com.prueba.login.repository.UsuarioRepository;
import com.prueba.login.service.UsuarioService;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Lazy
    @Autowired
    private AuthenticationManager authenticationManager;

    private final UsuarioService usuarioService;
    private final JwtAuthenticationFilter jwtUtils;
    private final UsuarioRepository usuarioRepository;

    public AuthController(UsuarioService usuarioService, JwtAuthenticationFilter jwtUtils, UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
        this.usuarioService = usuarioService;
        this.jwtUtils = jwtUtils;
    }

    /**
     * Genera un token JWT
     */
    @PostMapping("/token")
    public ResponseEntity<?> generarToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        try {
            autenticar(jwtRequest.getUsername(),jwtRequest.getPassword());
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Usuario no encontrado");
        }
        UserDetails userDetails = this.usuarioService.loadUserByUsername(jwtRequest.getUsername());
        String token = this.jwtUtils.generateToken(userDetails);
        return ResponseEntity.ok(new JwtResponse(token));
    }

    private void autenticar(String username, String password) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException | BadCredentialsException disabledException){
            throw new Exception("USUARIO DESHABILITADO" + disabledException.getMessage());
        }
    }

    /**
     * Valida un token JWT
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(401).build();
            }

            String token = authHeader.substring(7);

            var claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();

            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("username", claims.getSubject());
            response.put("expires", claims.getExpiration());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error validando token: {}", e.getMessage());
            Map<String, Object> response = new HashMap<>();
            response.put("valid", false);
            response.put("error", "Token inválido");
            return ResponseEntity.status(401).body(response);
        }
    }

    @GetMapping("/actual-usuario")
    public ResponseEntity<?> obtenerUsuarioActual(Principal principal) {

        UserDetails userDetails = this.usuarioService.loadUserByUsername(principal.getName());

        // Buscar el Usuario correspondiente en la base de datos
        Usuario usuario = usuarioRepository.findByUsername(userDetails.getUsername());

        if (usuario != null) {
            // Convertir Usuario a DTO y devolverlo
            return ResponseEntity.ok(UsuarioResponseDTO.fromUsuario(usuario));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Usuario no encontrado");
        }
    }
}

