package pw.react.backend.web;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import jakarta.validation.constraints.Email;
import pw.react.backend.models.Role;
import pw.react.backend.models.User;
import pw.react.backend.utils.JsonRoleDeserializer;
import pw.react.backend.utils.JsonRoleSerializer;

import java.util.Collection;

public record UserDto(
        Long id,
        String username,
        String password,
        @Email String email,
        @JsonSerialize(using = JsonRoleSerializer.class) @JsonDeserialize(using = JsonRoleDeserializer.class)
        Collection<String> roles) {

    public static UserDto valueFrom(User user) {
        return new UserDto(user.getId(), user.getUsername(), null, user.getEmail(), user.getRoles().stream().map(Role::getName).toList());
    }

    public static User convertToUser(UserDto userDto) {
        User user = new User();
        user.setId(userDto.id());
        user.setUsername(userDto.username());
        user.setEmail(userDto.email());
        user.setPassword(userDto.password());
        user.setRoles(userDto.roles().stream().map(Role::new).toList());
        return user;
    }
}
