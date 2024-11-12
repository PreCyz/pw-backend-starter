package pw.react.backend.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pw.react.backend.dao.UserRepository;
import pw.react.backend.exceptions.UserValidationException;
import pw.react.backend.models.User;

import java.util.*;

public class UserMainService implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserMainService.class);

    protected final UserRepository userRepository;

    public UserMainService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User validateAndSave(User user) {
        if (isValidUser(user)) {
            log.info("User is valid");
            Optional<User> dbUser = userRepository.findByUsername(user.getUsername());
            if (dbUser.isPresent()) {
                log.info("User already exists. Updating it.");
                user.setId(dbUser.get().getId());
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
            if (isInvalid(user.getEmail())) {
                log.error("Empty email.");
                throw new UserValidationException("Empty email.");
            }
            return true;
        }
        log.error("User is null.");
        throw new UserValidationException("User is null.");
    }

    private boolean isInvalid(String value) {
        return value == null || value.isBlank();
    }

    @Override
    public Collection<User> batchSave(Collection<User> users) {
        if (users != null && !users.isEmpty()) {
            for (User user : users) {
                isValidUser(user);
            }
            return userRepository.saveAll(users);
        } else {
            log.warn("User collection is empty or null.");
            return Collections.emptyList();
        }
    }
}
