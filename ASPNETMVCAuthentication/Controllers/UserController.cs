using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using ASPNETMVCAuthentication.Models;

namespace ASPNETMVCAuthentication.Controllers
{
    public class UserController : Controller
    {
       //Registerion Action
       [HttpGet]
       public ActionResult Registration()
        {

            return View();
        }

        //Registration POST action
        //https://www.youtube.com/watch?v=gSJFjuWFTdA
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude ="IsEmailVerified, ActivationCode")] User user)
        {
            bool Status = false;
            string message = "";
            // Model Validation
            if (ModelState.IsValid)
            {
                #region Email is already Exist
                var isExist = IsEmailExist(user.EmailID);

                if (isExist)
                {
                    // Email is already Exist
                    ModelState.AddModelError("EmailExist", "Email is already Exist");
                    return View(user);
                }
                #endregion

                #region Generate ActivationCode
                user.ActivationCode = Guid.NewGuid();
                #endregion

                #region Password Hashing
                user.Password = Crypto.Hash(user.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword);
                #endregion

                user.IsEmailVerified = 0;

                #region Save to Database
                using(MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    dc.Users.Add(user);
                    dc.SaveChanges();
                    // Send email to user
                    SendVerificationLinkEmail(user.EmailID, user.ActivationCode.ToString());
                    message = "Registeration successfully done. Account activation link" +
                        "has been sent to your email id:" + user.EmailID;

                    Status = true;
                }
                #endregion


            }
            else
            {
                message = "Invalid Request";
            }

            ViewBag.Message = message;
            ViewBag.Status = Status;

            return View(user);
        }


        //Verify Email LINK

        //Login

        //Login POST

        //Logout


        [NonAction]
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }

        [NonAction]
        public void SendVerificationLinkEmail(string emailID, string activationCode)
        {
            var verifyUrl = "/User/VerifyAccount/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("hoanghai.itcmu@gmail.com","Dotnet Awesome");
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "Hoanghai1991"; //Replace with actual password.
            string subject = "Your account is successfully created";

            string body = "<br/> We are excited to tell you that your account is "+
                "Successfully created. Please click on the below link to verify your " +
                "account <br/> <a href='"+link+"'>'"+link+"'</a>";

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })

            smtp.Send(message);
        }
    }
}