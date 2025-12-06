package pw.react.backend.dto.outbound;

public record UploadFileResponse(String fileName, String fileDownloadUri, String fileType, long size) { }
