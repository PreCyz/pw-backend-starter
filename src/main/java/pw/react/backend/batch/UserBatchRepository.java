package pw.react.backend.batch;

import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import pw.react.backend.models.User;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;

class UserBatchRepository implements BatchRepository<User> {
    private final JdbcTemplate jdbcTemplate;
    UserBatchRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public Collection<User> insertAll(Collection<User> entities) {
        String sql = "INSERT INTO `USER` (EMAIL, USERNAME) VALUES(?,?)";

        final var users = new ArrayList<>(entities);
        jdbcTemplate.batchUpdate(sql, new BatchPreparedStatementSetter() {
            @Override
            public void setValues(PreparedStatement ps, int i) throws SQLException {
                User user = users.get(i);
                ps.setString(1, user.getEmail());
                ps.setString(2, user.getUsername());
            }
            @Override
            public int getBatchSize() {
                return users.size();
            }
        });
        return users;
    }
}
