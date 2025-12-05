package pw.react.backend.batch;

import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import pw.react.backend.dao.CompanyRepository;
import pw.react.backend.models.Company;
import pw.react.backend.services.CompanyService;

@Profile({"batch", "*mysql*"})
public class BatchConfig {

    private final DataSource dataSource;

    public BatchConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Bean
    public NamedParameterJdbcTemplate namedParameterJdbcTemplate() {
        return new NamedParameterJdbcTemplate(dataSource);
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
    public BatchRepository<Company> companyBatchRepository(JdbcTemplate jdbcTemplate, NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        return new CompanyBatchRepository(jdbcTemplate, namedParameterJdbcTemplate);
    }

}
