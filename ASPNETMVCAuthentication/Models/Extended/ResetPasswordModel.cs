using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace ASPNETMVCAuthentication.Models.Extended
{
    public class ResetPasswordModel
    {
        [Required(ErrorMessage = "New Password Required", AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "New password and cofirm password does not match")]
        public string ConfirmPassword { get; set; }
        public string ResetCode { get; set; }

    }
}