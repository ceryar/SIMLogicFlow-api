package com.simlogicflow.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.simlogicflow.dto.DocumentTypeDto;
import com.simlogicflow.model.DocumentType;
import com.simlogicflow.service.DocumentTypeService;

@RestController
@RequestMapping("/api/v1/document-types")
@PreAuthorize("hasAuthority('ADMINISTRADOR')")
public class DocumentTypeController {

    @Autowired
    private DocumentTypeService documentTypeService;

    @GetMapping
    public List<DocumentType> getAllDocumentTypes() {
        return documentTypeService.getAllDocumentTypes();
    }

    @PostMapping
    public DocumentType createDocumentType(@RequestBody DocumentTypeDto dto) {
        return documentTypeService.createDocumentType(dto);
    }

    @PutMapping("/{id}")
    public DocumentType updateDocumentType(@PathVariable Long id, @RequestBody DocumentTypeDto dto) {
        return documentTypeService.updateDocumentType(id, dto);
    }

    @DeleteMapping("/{id}")
    public void deleteDocumentType(@PathVariable Long id) {
        documentTypeService.deleteDocumentType(id);
    }

}
