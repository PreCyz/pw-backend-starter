package pw.react.backend.dto.request;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateCompanyRequest {

    @NotBlank(message = "Name is mandatory")
    private String name;

    @Min(value = 1, message = "Board members must be at least 1")
    private int boardMembers;
}
