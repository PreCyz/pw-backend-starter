package pw.react.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import pw.react.backend.repositories.CompanyRepository;
import pw.react.backend.services.CompanyMainService;
import pw.react.backend.services.CompanyService;

@Profile("!batch")
public class NonBatchConfig {

    @Bean
    public CompanyService companyService(CompanyRepository companyRepository) {
        return new CompanyMainService(companyRepository);
    }

}
