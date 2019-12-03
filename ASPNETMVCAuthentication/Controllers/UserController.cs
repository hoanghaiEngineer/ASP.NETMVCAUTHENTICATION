using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using ASPNETMVCAuthentication.Models;
using ASPNETMVCAuthentication.Models.Extended;
using Facebook;

namespace ASPNETMVCAuthentication.Controllers
{
    public class UserController : Controller
    {
        private Uri RedirectUri
        {
            get
            {
                var uriBuilder = new UriBuilder(Request.Url);
                uriBuilder.Query = null;
                uriBuilder.Fragment = null;
                uriBuilder.Path = Url.Action("FacebookCallback");
                return uriBuilder.Uri;
            }
        }
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


        //Verify Account
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;

            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; // This line I have added here to avoid
                                                                // Confirm password that not match issue on save change
                var v = dc.Users.Where(a=>a.ActivationCode == new Guid(id)).FirstOrDefault();
                if(v != null)
                {
                    v.IsEmailVerified = 1;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }

        //Login
        [HttpGet]
        public ActionResult Login()
        {
            //https://www.youtube.com/watch?v=qGbpfgVm-M4
            //https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/create-an-aspnet-mvc-5-app-with-facebook-and-google-oauth2-and-openid-sign-on
            return View();
        }

        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin login, string returnUrl)
        {
            string message = "";
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == login.EmailID).FirstOrDefault();
                if(v != null)
                {
                    if (string.Compare(Crypto.Hash(login.Password), v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 5256000 : 20; // 5256000 = 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID,login.RememberMe, timeout) ;
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);

                        if (Url.IsLocalUrl(returnUrl))
                        {
                            return Redirect(returnUrl);
                        }
                        else
                        {
                            return RedirectToAction("Index", "Home");
                        }
                    }
                }
                else
                {
                    message = "Invalid credential provided";
                }
            }
            ViewBag.Message = message;
            return View();
        }

        public ActionResult LoginFacebook()
        {
            var fb = new FacebookClient();
            var loginUrl = fb.GetLoginUrl(new
            {
                client_id = ConfigurationManager.AppSettings["FbAppId"],
                client_secret = ConfigurationManager.AppSettings["FbAppSecret"],
                redirect_uri = RedirectUri.AbsoluteUri,
                response_type = "code",
                scope = "email"
            });

            return Redirect(loginUrl.AbsoluteUri);
        }

        public ActionResult FacebookCallback(string code)
        {
            var fb = new FacebookClient();
            long resultInsert = 0;
            dynamic result = fb.Post("oauth/access_token", new
            {
                client_id = ConfigurationManager.AppSettings["FbAppId"],
                client_secret = ConfigurationManager.AppSettings["FbAppSecret"],
                redirect_uri = RedirectUri.AbsoluteUri,
                code = code
            });

            var accessToken = result.access_token;

            if (!string.IsNullOrEmpty(accessToken))
            {
                fb.AccessToken = accessToken;
                // Get the user's information, like email, firstname, middle name, last name, id, email
                dynamic me = fb.Get("me?fields=first_name, middle_name, last_name, id, email");
                string email = me.email;
                string username = me.email;
                string firstname = me.first_name;
                string middlename = me.middle_name;
                string lastname = me.last_name;

                var user = new User();
                user.EmailID = email;
                user.FirstName = firstname;
                user.LastName = lastname;

                resultInsert = InsertForFacebook(user);

                if(resultInsert > 0)
                {
                    var userSession = new UserLogin();
                    userSession.EmailID = user.EmailID;
                    Session.Add("userSession", userSession);
                }
            }

            if (resultInsert > 0)
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                return RedirectToAction("Login", "User");
            }
        }

        public long InsertForFacebook(User entity)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var user = dc.Users.SingleOrDefault(x => x.EmailID == entity.EmailID);
                if(user == null)
                {
                    entity.UserID = 0;
                    entity.Password = "123456789";
                    entity.ConfirmPassword = "123456789";
                    entity.ActivationCode = Guid.NewGuid();
                    entity.IsEmailVerified = 0;
                    dc.Users.Add(entity);
                    dc.SaveChanges();
                    return entity.UserID;
                }
                else
                {
                    return user.UserID;
                }
            }
        }

        //Logout
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }

        public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ForgotPassword(string EmailID)
        {
            //Verify Email ID
            //Generate reset password link
            //Send Email
            string message = "";
            bool status = false;

            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var account = dc.Users.Where(a => a.EmailID == EmailID).FirstOrDefault();
                if(account != null)
                {
                    // Send Email for reset password
                    string resetCode = Guid.NewGuid().ToString();
                    SendVerificationLinkEmail(account.EmailID, resetCode, "ResetPassword");
                    account.ResetPasswordCode = resetCode;
                    //This line I have added here to avoid confirm password not match issue,
                    //as we had added a confirm password property
                    //in our model class
                    dc.Configuration.ValidateOnSaveEnabled = false;
                    dc.SaveChanges();
                    message = "Reset password link has been sent to your email id.";
                }
                else
                {
                    message = "Account not found";
                }

                ViewBag.message = message;
                return View();
            }
        }

        public ActionResult ResetPassword(string id)
        {
            // Verify the reset password link

            // Find account associated with this link
            //redirect to reset password page
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var user = dc.Users.Where(a => a.ResetPasswordCode == id).FirstOrDefault();
                if(user != null)
                {
                    ResetPasswordModel model = new ResetPasswordModel();
                    model.ResetCode = id;
                    return View(model);
                }
                else
                {
                    return HttpNotFound();
                }
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(ResetPasswordModel model)
        {
            var message = "";
            if (ModelState.IsValid)
            {
                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    var user = dc.Users.Where(a => a.ResetPasswordCode == model.ResetCode).FirstOrDefault();
                    if (user != null)
                    {
                        user.Password = Crypto.Hash(model.NewPassword);
                        user.ResetPasswordCode = "";
                        dc.Configuration.ValidateOnSaveEnabled = false;
                        dc.SaveChanges();
                        message = "New password updated successfull";
                    }
                }
            }
            else
            {
                message = "Something invalid";
            }

            ViewBag.Message = message;
            return View(model);
        }
        //https://www.youtube.com/watch?v=7g2ptkiPLIg

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
        public void SendVerificationLinkEmail(string emailID, string activationCode, string emailFor = "verifyAccount")
        {
            var verifyUrl = "/User/" +emailFor + "/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("hoanghai.itcmu@gmail.com","Dotnet Awesome");
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "*********"; //Replace with actual password.
            string subject = "Your account is successfully created";
            string body = "";

            if(emailFor == "verifyAccount")
            {
                body = "<br/> We are excited to tell you that your account is " +
                "Successfully created. Please click on the below link to verify your " +
                "account <br/> <a href='" + link + "'>'" + link + "'</a>";
            }
            else if(emailFor == "ResetPassword")
            {
                subject = "Reset Password";
                body = "Hi,<br/><br/>We got request your account password. " +
                    "Please click on the below link to reset your password" +
                    "<br/><br/><a href="+link+">Reset Password link</a>";
            }

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

        //Social network using ASP.NET MVC
        //- We are building a social network application where user can add, edit 
        //  and delete their own pin boards and other user can pin their posts.
        //
    }
}