package pw.react.backend.services;

import lombok.extern.slf4j.Slf4j;
import pw.react.backend.domain.Company;
import pw.react.backend.repositories.BatchRepository;
import pw.react.backend.repositories.CompanyRepository;

import java.util.Collections;
import java.util.List;

@Slf4j
public class CompanyBatchService extends CompanyMainService {

    private final BatchRepository<Company> batchRepository;

    public CompanyBatchService(CompanyRepository repository, BatchRepository<Company> batchRepository) {
        super(repository);
        this.batchRepository = batchRepository;
    }

    @Override
    public List<Company> batchSave(List<Company> companies) {
        log.info("Batch insert.");
        if (companies != null && !companies.isEmpty()) {
            return batchRepository.insertAll(companies);
        } else {
            log.warn("Companies collection is empty or null.");
            return Collections.emptyList();
        }
    }
}
