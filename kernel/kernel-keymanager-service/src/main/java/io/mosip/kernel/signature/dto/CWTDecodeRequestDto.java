package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTDecodeRequestDto {

    @NotBlank
    @ApiModelProperty(notes = "Base45 CWT Signature data to verify", example = "eyJhbGciOiJIU.ewogICAiYW55S2V.5IjogIlRlc3QgSnNvbiIKfQ", required = true)
    private String cwtSignatureData;

    /**
     * Application id of decrypting module
     */
    @ApiModelProperty(notes = "Application id to be used for verification", example = "KERNEL", required = false)
    private String applicationId;

    /**
     * Refrence Id
     */
    @ApiModelProperty(notes = "Refrence Id", example = "SIGN", required = false)
    private String referenceId;

    /**
     * Flag to validate against trust store.
     */
    @ApiModelProperty(notes = "Flag to validate against trust store.", example = "false", required = false)
    private Boolean validateTrust;

    /**
     * Domain to be considered to validate trust store
     */
    @ApiModelProperty(notes = "Domain to be considered to validate trust store.", example = "", required = false)
    private String domain;
}
