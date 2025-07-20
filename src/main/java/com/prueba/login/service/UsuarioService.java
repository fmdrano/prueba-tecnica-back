package com.prueba.login.service;

import com.prueba.login.entity.Usuario;
import com.prueba.login.entity.UsuarioRol;
import com.prueba.login.repository.RolRepository;
import com.prueba.login.repository.UsuarioRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;
    private final RolRepository rolRepository;

    public UsuarioService(UsuarioRepository usuarioRepository, RolRepository rolRepository) {
        this.usuarioRepository = usuarioRepository;
        this.rolRepository = rolRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Intentando cargar usuario: {}", username);

        Usuario usuario = this.usuarioRepository.findByUsername(username);
        if (usuario == null) {
            log.error("Usuario no encontrado: {}", username);
            throw new UsernameNotFoundException("Usuario no encontrado");
        }
        log.info("Usuario encontrado - ID: {}, Username: {}, Password presente: {}",
                usuario.getId(), usuario.getUsername(), usuario.getPassword() != null);


        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        if (usuario.getUsuarioRoles() != null) {
            for (UsuarioRol usuarioRol : usuario.getUsuarioRoles()) {
                if (usuarioRol != null && usuarioRol.getRol() != null && usuarioRol.getRol().getRolNombre() != null) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(usuarioRol.getRol().getRolNombre()));
                }
            }
        }

        return new org.springframework.security.core.userdetails.User(
                usuario.getUsername(),
                usuario.getPassword(),
                usuario.isEnabled(),
                true,
                true,
                true,
                grantedAuthorities
        );
    }
}
