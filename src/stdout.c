/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "locking.h"
#include "rp_kernel_on_cpu.h"
#include "mpsp.h"
#include "opencl.h"
#include "stdout.h"
#include "policy_flag.h"

u32 plain_buf_save[16] = { 0 };
u32 plain_len_save =  0;

char pw_cnt[32] = {0};
int pw_cnt_len = 0;

static void increament_pw_cnt()
{
  //Assume we know that len(pw) = 32
  int i = 0;
  while (1)
  {
    if (pw_cnt[32-i-1] == 0) //Not initialized
    {
      pw_cnt[32-i-1] = '1';
      pw_cnt_len += 1; //New digit introduced
      break; //no carry
    }
    else if (pw_cnt[32-i-1] == '9')
    {
      pw_cnt[32-i-1] = '0'; //carry
    }
    else
    {
      pw_cnt[32-i-1] += 1;
      break; // no carry
    }
    i ++; 
  }
}

static int check_password_policy()
{
  return 1;
}


static void out_flush (out_t *out)
{
  if (out->len == 0) return;

  fwrite (out->buf, 1, out->len, out->fp);
  //printf("Policy Flag: %d, %d\n", check_length, check_number);

  out->len = 0;
}

static void out_push (out_t *out, const u8 *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);

  //#if defined (_WIN)

  //ptr[pw_len + 0] = '\r';
  //ptr[pw_len + 1] = '\n';

  //out->len += pw_len + 2;

  //#else

  ptr[pw_len] = '\t';

  out->len += pw_len + 1;

  //#endif

  if (out->len >= BUFSIZ - 100)
  {
    out_flush (out);
  }
}

static void out_push_original_word (out_t *out, const u8 *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);


  ptr[pw_len] = '\t';

  out->len += pw_len + 1;


  if (out->len >= BUFSIZ - 100)
  {
    out_flush (out);
  }
}

static void out_push_pw_count(out_t *out)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_cnt + 32 - pw_cnt_len, pw_cnt_len);

  ptr[pw_cnt_len] = '\n';

  out->len += pw_cnt_len + 1;

  if (out->len >= BUFSIZ - 100)
  {
    out_flush (out);
  }
}
int process_stdout (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 pws_cnt)
{
  //called twice
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  outfile_ctx_t    *outfile_ctx    = hashcat_ctx->outfile_ctx;
  straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  user_options_t   *user_options   = hashcat_ctx->user_options;

  out_t out;

  out.fp = stdout;

  char *filename = outfile_ctx->filename;

  if (filename)
  {
    FILE *fp = fopen (filename, "ab");

    if (fp == NULL)
    {
      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }

    if (lock_file (fp) == -1)
    {
      fclose (fp);

      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }

    out.fp = fp;
  }

  out.len = 0;

  u32 plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  u8 *plain_ptr_save = (u8 *) plain_buf_save;

  u32 plain_len = 0;



  const u32 il_cnt = device_param->kernel_params_buf32[30]; // ugly, i know

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    //printf("ATTACK_MODE_STRAIGHT\n");
    pw_t pw;

    //printf("%d\n", hashconfig->pw_max); -- result:31

    for (u32 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) fclose (out.fp);

        return -1;
      }

      const u32 pos = device_param->innerloop_pos;
      


      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        for (int i = 0; i < 8; i++)
        {
          plain_buf_save[i] = pw.i[i];
        }

        plain_len = pw.pw_len;
        plain_len_save = pw.pw_len;

        plain_len = apply_rules (straight_ctx->kernel_rules_buf[pos + il_pos].cmds, &plain_buf[0], &plain_buf[4], plain_len);

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;


        //increament_pw_cnt();
        if (check_password_policy() == 1)
        {
          out_push (&out, plain_ptr, plain_len);
          out_push_original_word (&out, plain_ptr_save, plain_len_save);
          out_push_pw_count(&out);
        }
        
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    for (u32 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) fclose (out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
        u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

        if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          memcpy (plain_ptr + plain_len, comb_buf, comb_len);
        }
        else
        {
          memmove (plain_ptr + comb_len, plain_ptr, plain_len);

          memcpy (plain_ptr, comb_buf, comb_len);
        }

        plain_len += comb_len;

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    for (u32 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
        u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

        u32 l_start = device_param->kernel_params_mp_l_buf32[5];
        u32 r_start = device_param->kernel_params_mp_r_buf32[5];

        u32 l_stop = device_param->kernel_params_mp_l_buf32[4];
        u32 r_stop = device_param->kernel_params_mp_r_buf32[4];

        sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
        sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

        plain_len = mask_ctx->css_cnt;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    for (u32 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) fclose (out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

        u32 start = 0;
        u32 stop  = device_param->kernel_params_mp_buf32[4];

        sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len += start + stop;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    for (u32 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1)
      {
        if (filename) fclose (out.fp);

        return -1;
      }

      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

        u32 start = 0;
        u32 stop  = device_param->kernel_params_mp_buf32[4];

        memmove (plain_ptr + stop, plain_ptr, plain_len);

        sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len += start + stop;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }

  out_flush (&out);

  if (filename) fclose (out.fp);

  return 0;
}
