package io.mosip.kernel.signature.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTSignatureVerifyResponseDto {

    /**
     * The Signature verification status.
     */
    private boolean signatureValid;

    /**
     * The Signature validation message.
     */
    private String message;
}
