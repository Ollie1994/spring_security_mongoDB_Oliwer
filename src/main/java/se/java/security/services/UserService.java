package se.java.security.services;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import se.java.security.models.Role;
import se.java.security.models.User;
import se.java.security.repository.UserRepository;

import java.util.Set;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public void registerUser(User user) {
        // hash password
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        // ensure the user has at least default role USER
        if (user.getRoles() == null || user.getRoles().isEmpty()) {
            user.setRoles(Set.of(Role.USER));
        }
        userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).
                orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public boolean existsByUsername(String username) {
        return userRepository.findByUsername(username).isPresent();

    }












}
