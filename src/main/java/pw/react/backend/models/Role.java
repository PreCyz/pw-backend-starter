package pw.react.backend.models;

import jakarta.persistence.*;

import java.util.*;
import java.util.stream.Collectors;

@Entity
public class Role {

    public enum Value {
        ADMIN, INTEGRATION, USER;
        public static Set<String> allRoles() {
            return EnumSet.allOf(Value.class).stream().map(Enum::name).collect(Collectors.toSet());
        }

        public static String valueFrom(String name) {
            if (name != null && !name.startsWith("ROLE")) {
                return "ROLE_" + name;
            }
            return name;
        }
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    @ManyToMany(mappedBy = "roles")
    private Collection<User> users;

    @ManyToMany
    @JoinTable(
            name = "roles_privileges",
            joinColumns = @JoinColumn(
                    name = "role_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(
                    name = "privilege_id", referencedColumnName = "id"))
    private Collection<Privilege> privileges;

    public Role() {}

    public Role(String name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Collection<User> getUsers() {
        return users;
    }

    public void setUsers(Collection<User> users) {
        this.users = users;
    }

    public Collection<Privilege> getPrivileges() {
        return privileges;
    }

    public void setPrivileges(Collection<Privilege> privileges) {
        this.privileges = privileges;
    }
}
