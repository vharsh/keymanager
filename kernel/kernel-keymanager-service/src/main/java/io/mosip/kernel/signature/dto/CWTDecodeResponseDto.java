package io.mosip.kernel.signature.dto;

import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTDecodeResponseDto {

    /**
     * Data Encrypted/Decrypted in Base45 encoding
     */
    @ApiModelProperty(notes = "Data encrypted/decrypted in BASE64 encoding")
    private String data;
}
