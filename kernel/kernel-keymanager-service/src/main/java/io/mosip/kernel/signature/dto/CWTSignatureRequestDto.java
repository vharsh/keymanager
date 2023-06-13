package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTSignatureRequestDto {


    @NotBlank
    @ApiModelProperty(notes = "CWT coseid", example = "key", required = true)
    private String coseId;

    @NotBlank
    @ApiModelProperty(notes = "Base64 encoded JSON Data to sign", example = "ewogICAiYW55S2V5IjogIlRlc3QgSnNvbiIKfQ", required = true)
    private String dataToSign;

    /**
     * Application id of decrypting module
     */
    @ApiModelProperty(notes = "Application id to be used for signing", example = "KERNEL", required = false)
    private String applicationId;

    /**
     * Refrence Id
     */
    @ApiModelProperty(notes = "Refrence Id", example = "SIGN", required = false)
    private String referenceId;

}
