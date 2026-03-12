package com.simlogicflow.dto;

import lombok.*;
@Getter // para que la clase Lombook cree kis get
@Setter // para que la clase Lombook cree kis set
@NoArgsConstructor // crea construtor sin parametros
@AllArgsConstructor // constructor con parametros 

public class UserDto {

   
    private String firstName;

    private String middleName;

    private String lastname;

    private String secondlasname;

    private String email;

    private String password;

    private Boolean active;

    private String documentNumber;

    private Long roleId;

    private Long documentTypeId;

    //private Set<Long> courseIds;

}
