package pw.react.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import pw.react.backend.domain.Company;
import pw.react.backend.repositories.*;
import pw.react.backend.services.CompanyBatchService;
import pw.react.backend.services.CompanyService;

import javax.sql.DataSource;

@Profile({"batch", "*mysql*"})
public class BatchConfig {

    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate(DataSource dataSource) {
        return new NamedParameterJdbcTemplate(dataSource);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public CompanyService companyService(CompanyRepository companyRepository, BatchRepository<Company> companyBatchRepository) {
        return new CompanyBatchService(companyRepository, companyBatchRepository);
    }

    @Bean
    public BatchRepository<Company> companyBatchRepository(JdbcTemplate jdbcTemplate, NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        return new CompanyBatchRepository(jdbcTemplate, namedParameterJdbcTemplate);
    }

}
