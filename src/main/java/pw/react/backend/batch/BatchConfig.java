package pw.react.backend.batch;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import pw.react.backend.dao.*;
import pw.react.backend.models.Company;
import pw.react.backend.models.User;
import pw.react.backend.services.CompanyService;
import pw.react.backend.services.UserService;

import javax.sql.DataSource;

@Profile({"batch", "*mysql*"})
public class BatchConfig {

    private final DataSource dataSource;

    public BatchConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public JdbcTemplate jdbcTemplate() {
        return new JdbcTemplate(dataSource);
    }
    @Bean
    public CompanyService companyService(CompanyRepository companyRepository, BatchRepository<Company> companyBatchRepository) {
        return new CompanyBatchService(companyRepository, companyBatchRepository);
    }

    @Bean
    public UserService userService(UserRepository userRepository,
                                   PasswordEncoder passwordEncoder,
                                   BatchRepository<User> userBatchRepository,
                                   RoleRepository roleRepository) {
        return new UserBatchService(userRepository, passwordEncoder, userBatchRepository, roleRepository);
    }

    @Bean
    public CompanyBatchRepository companyBatchRepository(JdbcTemplate jdbcTemplate) {
        return new CompanyBatchRepository(jdbcTemplate);
    }

    @Bean
    public UserBatchRepository userBatchRepository(JdbcTemplate jdbcTemplate) {
        return new UserBatchRepository(jdbcTemplate);
    }
}
