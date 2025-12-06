package pw.react.backend.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import pw.react.backend.domain.Company;

public interface CompanyRepository extends JpaRepository<Company, Long> {
}
