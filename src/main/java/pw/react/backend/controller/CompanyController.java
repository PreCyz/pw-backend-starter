package pw.react.backend.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import pw.react.backend.domain.Company;
import pw.react.backend.domain.CompanyLogo;
import pw.react.backend.dto.mapper.CompanyMapper;
import pw.react.backend.dto.request.CreateCompanyRequest;
import pw.react.backend.dto.request.UpdateCompanyRequest;
import pw.react.backend.dto.response.*;
import pw.react.backend.exceptions.ResourceNotFoundException;
import pw.react.backend.services.CompanyLogoService;
import pw.react.backend.services.CompanyService;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Stream;

import static java.util.stream.Collectors.joining;

@RestController
@RequestMapping(path = CompanyController.COMPANIES_PATH)
@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class CompanyController {

    public static final String COMPANIES_PATH = "/companies";

    private final CompanyService companyService;
    private final CompanyMapper companyMapper;
    private final CompanyLogoService companyLogoService;

    @PostMapping(path = "")
    public ResponseEntity<Collection<CompanyResponse>> createCompanies(@RequestHeader HttpHeaders headers,
                                                                       @Valid @RequestBody List<CreateCompanyRequest> companies) {
        logHeaders(headers);
        List<Company> createdCompanies = companyMapper.createRequestToCompanyList(companies);
        List<CompanyResponse> result = companyMapper.companyToResponseList(companyService.batchSave(createdCompanies));
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    private void logHeaders(@RequestHeader HttpHeaders headers) {
        log.info("Controller request headers {}",
                headers.entrySet()
                        .stream()
                        .map(entry -> String.format("%s->[%s]", entry.getKey(), String.join(",", entry.getValue())))
                        .collect(joining(","))
        );
    }

    @GetMapping(path = "/{companyId}")
    public ResponseEntity<GetCompanyResponse> getCompany(@RequestHeader HttpHeaders headers, @PathVariable Long companyId) {
        logHeaders(headers);
        GetCompanyResponse result = companyService.getById(companyId)
                .map(companyMapper::companyToGetCompanyResponse)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Company with %d does not exist", companyId)));
        return ResponseEntity.ok(result);
    }

    @GetMapping
    public ResponseEntity<List<GetCompanyResponse>> getAllCompanies(@RequestHeader HttpHeaders headers,
                                                                 @RequestParam(required = false) Integer page,
                                                                 @RequestParam(required = false) Integer size) {
        logHeaders(headers);
        if (page == null || size == null) {
            return ResponseEntity.ok(companyMapper.companyToGetCompanyResponseList(companyService.getAll()));
        }
        return ResponseEntity.ok(companyMapper.companyToGetCompanyResponseList(companyService.getCompaniesPage(page, size)));
    }

    @PutMapping(path = "/{companyId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void updateCompany(@RequestHeader HttpHeaders headers, @PathVariable Long companyId,
                              @Valid @RequestBody UpdateCompanyRequest updatedCompany) {
        logHeaders(headers);
        companyService.updateCompany(companyId, companyMapper.updateRequestToCompany(updatedCompany));
    }

    @DeleteMapping(path = "/{companyId}")
    public ResponseEntity<String> deleteCompany(@RequestHeader HttpHeaders headers, @PathVariable Long companyId) {
        logHeaders(headers);
        boolean deleted = companyService.deleteCompany(companyId);
        if (!deleted) {
            return ResponseEntity.badRequest().body(String.format("Company with id %s does not exists.", companyId));
        }
        return ResponseEntity.ok(String.format("Company with id %s deleted.", companyId));
    }

    @PostMapping("/{companyId}/logo")
    public ResponseEntity<UploadFileResponse> uploadLogo(@RequestHeader HttpHeaders headers,
                                                         @PathVariable Long companyId,
                                                         @RequestParam("file") MultipartFile file) {
        logHeaders(headers);
        CompanyLogo companyLogo = companyLogoService.storeLogo(companyId, file);

        String fileDownloadUri = ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/companies/" + companyId + "/logo/")
                .path(companyLogo.getFileName())
                .toUriString();
        UploadFileResponse response = new UploadFileResponse(
                companyLogo.getFileName(),
                fileDownloadUri,
                file.getContentType(),
                file.getSize()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping(value = "/{companyId}/logo", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public @ResponseBody byte[] getLog(@RequestHeader HttpHeaders headers, @PathVariable Long companyId) {
        logHeaders(headers);
        CompanyLogo companyLogo = companyLogoService.getCompanyLogo(companyId);
        return companyLogo.getData();
    }

    @Operation(summary = "Get logo for company")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Get log by company id",
                    content = {@Content(mediaType = "application/json")}
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized operation",
                    content = {@Content(mediaType = "application/json")}
            )
    })
    @GetMapping(value = "/{companyId}/logo2")
    public ResponseEntity<Resource> getLogo2(@RequestHeader HttpHeaders headers, @PathVariable Long companyId) {
        logHeaders(headers);
        CompanyLogo companyLogo = companyLogoService.getCompanyLogo(companyId);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(companyLogo.getFileType()))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + companyLogo.getFileName() + "\"")
                .body(new ByteArrayResource(companyLogo.getData()));
    }

    @Operation(summary = "Delete logo for given company")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "204",
                    description = "Logo deleted",
                    content = {@Content(mediaType = "application/json")}
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Unauthorized operation",
                    content = {@Content(mediaType = "application/json")}
            )
    })
    @DeleteMapping(value = "/{companyId}/logo")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void removeLogo(@RequestHeader HttpHeaders headers, @PathVariable String companyId) {
        logHeaders(headers);
        companyLogoService.deleteCompanyLogo(Long.parseLong(companyId));
    }

    @PostMapping(path = "/benchmark/{size}")
    public ResponseEntity<String> benchmark(@RequestHeader HttpHeaders headers, @PathVariable(name = "size") int size) {
        logHeaders(headers);
        LocalDateTime start = LocalDateTime.now();
        companyService.batchSave(Stream.generate(() -> {
            Company company = new Company();
            company.setStartDateTime(LocalDateTime.now());
            company.setName(UUID.randomUUID().toString());
            company.setBoardMembers(new Random().nextInt(100));
            return company;
        }).limit(size).toList());
        Duration duration = Duration.between(start, LocalDateTime.now());
        String message = String.format("Benchmark - insert %d records, took %d sec", size, duration.getSeconds());
        log.info(message);
        return ResponseEntity.ok(message);
    }

}
