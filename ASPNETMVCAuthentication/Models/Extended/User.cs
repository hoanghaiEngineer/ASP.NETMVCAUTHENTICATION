﻿using System;
using System.ComponentModel.DataAnnotations;

namespace ASPNETMVCAuthentication.Models
{
    [MetadataType(typeof(UserMetaData))]
    public partial class User
    {
        public string ConfirmPassword { get; set; }
    }

    public class UserMetaData
    {
        [Display (Name = "First Name")]
        [Required(AllowEmptyStrings =false, ErrorMessage = "First name required")]
        public string FirstName { get; set; }

        [Display(Name = "Last Name")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Last name required")]
        public string LastName { get; set; }

        [Display(Name = "Email ID")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Email ID required")]
        [DataType(DataType.EmailAddress)]
        public string EmailID { get; set; }

        [Display(Name = "Date of Birth")]
        [DataType(DataType.DateTime)]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString = "{0:MM-dd-yyyy}")]
        public DateTime DateOfBirth { get; set; }


        [Required(AllowEmptyStrings =false, ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        [MinLength(6,ErrorMessage = "Minimum 6 characters required")]
        public string Password { get; set; }

        [Display(Name = "Confirm Password")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Minimum 6 characters required")]
        [Compare("Password",ErrorMessage ="Confirm password doesn't match")]
        public string ConfirmPassword { get; set; }
    }
}