package pw.react.backend.batch;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.core.namedparam.SqlParameterSourceUtils;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.transaction.annotation.Transactional;
import pw.react.backend.models.Company;

class CompanyBatchRepository implements BatchRepository<Company> {
    private final static Logger logger = LoggerFactory.getLogger(CompanyBatchRepository.class);
    private final JdbcTemplate jdbcTemplate;
    private final NamedParameterJdbcTemplate namedParameterJdbcTemplate;

    CompanyBatchRepository(JdbcTemplate jdbcTemplate, NamedParameterJdbcTemplate namedParameterJdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.namedParameterJdbcTemplate = namedParameterJdbcTemplate;
    }

    @Override
    @Transactional
    public Collection<Company> insertAll(Collection<Company> entities) {
        String sql = "INSERT INTO `COMPANY` (NAME, BOARD_MEMBERS, START_DATE) VALUES(?,?,?)";

        for (Company company : entities) {
            company.setStartDateTime(
                    Optional.ofNullable(company.getStartDateTime())
                            .orElseGet(() -> Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime())
            );
        }
        final var companies = new ArrayList<>(entities);
        KeyHolder keyHolder = new GeneratedKeyHolder();

        PreparedStatementCreator psc = connection -> connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);

        jdbcTemplate.batchUpdate(psc, createBatchPreparedStatementSetter(companies), keyHolder);

        setIdsFromKeyHolder(keyHolder, companies);
        return companies;
    }

    private BatchPreparedStatementSetter createBatchPreparedStatementSetter(ArrayList<Company> companies) {
        return new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                Company company = companies.get(i);
                ps.setString(1, company.getName());
                ps.setInt(2, company.getBoardMembers());
                ps.setDate(3, new java.sql.Date(ZonedDateTime.of(company.getStartDateTime(), ZoneId.systemDefault()).toInstant().toEpochMilli()));
            }

            @Override
            public int getBatchSize() {
                return companies.size();
            }
        };
    }

    @Transactional
    public Collection<Company> insertAll1(Collection<Company> companies) {
        String sql = "INSERT INTO `COMPANY` (NAME, BOARD_MEMBERS, START_DATE) VALUES(:name, :boardMembers, :startDateTime)";

        List<Company> cpyCompanies = new ArrayList<>(companies);

        for (Company company : cpyCompanies) {
            company.setStartDateTime(
                    Optional.ofNullable(company.getStartDateTime())
                            .orElseGet(() -> Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime())
            );
        }

        SqlParameterSource[] batch = SqlParameterSourceUtils.createBatch(companies.toArray());
        KeyHolder keyHolder = new GeneratedKeyHolder();

        namedParameterJdbcTemplate.batchUpdate(sql, batch, keyHolder);

        setIdsFromKeyHolder(keyHolder, cpyCompanies);

        logger.info("{} companies inserted", companies.stream().map(Company::getId).toList());
        return companies;
    }

    private void setIdsFromKeyHolder(KeyHolder keyHolder, List<Company> cpyCompanies) {
        // Extract generated keys and set them back to companies
        List<Map<String, Object>> keyList = keyHolder.getKeyList();
        for (int i = 0; i < keyList.size() && i < cpyCompanies.size(); i++) {
            Map<String, Object> keys = keyList.get(i);
            Object generatedId = keys.get("GENERATED_KEY"); // or keys.get("ID") depending on your DB
            if (generatedId != null) {
                cpyCompanies.get(i).setId(((Number) generatedId).longValue());

            }
        }
    }

}
