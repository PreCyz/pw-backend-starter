package pw.react.backend.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import pw.react.backend.domain.CompanyLogo;

import java.util.Optional;

@Transactional
public interface CompanyLogoRepository extends JpaRepository<CompanyLogo, String> {
    Optional<CompanyLogo> findByCompanyId(long companyId);
    void deleteByCompanyId(long companyId);
}
