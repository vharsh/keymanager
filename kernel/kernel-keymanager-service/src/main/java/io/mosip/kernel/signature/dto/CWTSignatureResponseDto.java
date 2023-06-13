package io.mosip.kernel.signature.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CWTSignatureResponseDto {
    /**
     * signed CWT data
     */
    private String cwtSignedData;

    /**
     * CWT sign time.
     */
    private LocalDateTime timestamp;

}
