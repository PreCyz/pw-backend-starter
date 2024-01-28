package pw.react.backend.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import pw.react.backend.dao.RoleRepository;
import pw.react.backend.dao.UserRepository;
import pw.react.backend.exceptions.UserValidationException;
import pw.react.backend.models.Role;
import pw.react.backend.models.User;

import java.util.*;

import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;

public class UserMainService implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserMainService.class);

    protected final UserRepository userRepository;
    protected final PasswordEncoder passwordEncoder;
    protected final RoleRepository roleRepository;

    public UserMainService(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    @Override
    public User validateAndSave(User user) {
        if (isValidUser(user)) {
            log.info("User is valid");
            Optional<User> dbUser = userRepository.findByUsername(user.getUsername());
            if (dbUser.isPresent()) {
                log.info("User already exists. Updating it.");
                user.setId(dbUser.get().getId());
                user.setPassword(passwordEncoder.encode(user.getPassword()));
                user.setRoles(roleRepository.findByNameIn(user.getRoles().stream().map(Role::getName).collect(toSet())));
            }
            user = userRepository.save(user);
            log.info("User was saved.");
        }
        return user;
    }

    private boolean isValidUser(User user) {
        if (user != null) {
            if (isInvalid(user.getUsername())) {
                log.error("Empty username.");
                throw new UserValidationException("Empty username.");
            }
            if (isInvalid(user.getPassword())) {
                log.error("Empty user password.");
                throw new UserValidationException("Empty user password.");
            }
            if (isInvalid(user.getEmail())) {
                log.error("Empty email.");
                throw new UserValidationException("Empty email.");
            }
            if (isInvalidRole(user.getRoles())) {
                log.error("Invalid user role.");
                throw new UserValidationException("Invalid user role.");
            }
            return true;
        }
        log.error("User is null.");
        throw new UserValidationException("User is null.");
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }

    private boolean isInvalidRole(Collection<Role> roles) {
        Set<String> roleNames = roles.stream().map(Role::getName).collect(toSet());
        Set<String> allRoles = roleRepository.findAll()
                .stream()
                .map(Role::getName)
                .collect(toSet());
        return !allRoles.containsAll(roleNames);
    }

    protected void setRoles(Collection<User> users) {
        Set<String> roleNames = users.stream()
                .map(User::getRoles)
                .flatMap(Collection::stream)
                .map(it -> Role.Value.valueFrom(it.getName()))
                .collect(toSet());
        Map<String, Role> roleMap = roleRepository.findByNameIn(roleNames).stream().collect(toMap(Role::getName, v -> v, (v1, v2) -> v1));
        for (User user : users) {
            List<Role> roles = new ArrayList<>(user.getRoles().size());
            for (Role role : user.getRoles()) {
                roles.add(roleMap.get(role.getName()));
            }
            user.setRoles(roles);
        }
    }

    @Override
    public User updatePassword(User user, String password) {
        if (isValidUser(user)) {
            if (passwordEncoder != null) {
                log.debug("Encoding password.");
                user.setPassword(passwordEncoder.encode(password));
            } else {
                log.debug("Password in plain text.");
                user.setPassword(password);
            }
            user = userRepository.save(user);
        }
        return user;
    }

    @Override
    public Collection<User> batchSave(Collection<User> users) {
        if (users != null && !users.isEmpty()) {
            for (User user : users) {
                isValidUser(user);
                user.setPassword(passwordEncoder.encode(user.getPassword()));
            }
            setRoles(users);
            return userRepository.saveAll(users);
        } else {
            log.warn("User collection is empty or null.");
            return Collections.emptyList();
        }
    }
}
