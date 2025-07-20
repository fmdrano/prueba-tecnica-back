package com.prueba.login.dto;

import com.prueba.login.entity.Rol;
import com.prueba.login.entity.Usuario;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UsuarioResponseDTO {

    private Long id;
    private String username;
    private String nombre;
    private String apellido;
    private String email;
    private String telefono;
    private boolean enabled;
    private String perfil;
    //private Collection<? extends GrantedAuthority> authorities;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean accountNonExpired;
    private List<String> authorities;

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public static UsuarioResponseDTO fromUsuario(Usuario usuario) {
        log.info("Converting user {} to DTO", usuario.getId());

        UsuarioResponseDTO dto = new UsuarioResponseDTO();
        dto.setId(usuario.getId());
        dto.setUsername(usuario.getUsername());
        dto.setNombre(usuario.getNombre());
        dto.setApellido(usuario.getApellido());
        dto.setEmail(usuario.getEmail());
        dto.setTelefono(usuario.getTelefono());
        dto.setEnabled(usuario.isEnabled());
        dto.setPerfil(usuario.getPerfil());
        dto.setAccountNonLocked(usuario.isAccountNonLocked());
        dto.setCredentialsNonExpired(usuario.isCredentialsNonExpired());
        dto.setAccountNonExpired(usuario.isAccountNonExpired());

        List<String> authorities = new ArrayList<>();
        usuario.getUsuarioRoles().forEach(usuarioRol -> {
            Rol rol = usuarioRol.getRol();
            if (rol != null) {
                String authority = rol.getRolNombre().toUpperCase();
                //String authority = "ROLE_" + rol.getRolNombre().toUpperCase();
                authorities.add(authority);
            } else {
                log.warn("Null role found for user: {}", usuario.getId());
            }
        });
        dto.setAuthorities(authorities);
        return dto;
    }
}
