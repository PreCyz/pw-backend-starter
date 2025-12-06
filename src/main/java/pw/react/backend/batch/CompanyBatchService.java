package pw.react.backend.batch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pw.react.backend.dao.CompanyRepository;
import pw.react.backend.domain.Company;
import pw.react.backend.services.CompanyMainService;

import java.util.Collections;
import java.util.List;

class CompanyBatchService extends CompanyMainService {
    private final Logger logger = LoggerFactory.getLogger(CompanyBatchService.class);

    private final BatchRepository<Company> batchRepository;

    CompanyBatchService(CompanyRepository repository, BatchRepository<Company> batchRepository) {
        super(repository);
        this.batchRepository = batchRepository;
    }

    @Override
    public List<Company> batchSave(List<Company> companies) {
        logger.info("Batch insert.");
        if (companies != null && !companies.isEmpty()) {
            return batchRepository.insertAll(companies);
        } else {
            logger.warn("Companies collection is empty or null.");
            return Collections.emptyList();
        }
    }
}
