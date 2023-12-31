PGDMP                         {            mkptest    14.5    14.5 D    E           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            F           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            G           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            H           1262    47066    mkptest    DATABASE     l   CREATE DATABASE mkptest WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United Kingdom.1252';
    DROP DATABASE mkptest;
                postgres    false            �            1259    47390    failed_jobs    TABLE     &  CREATE TABLE public.failed_jobs (
    id bigint NOT NULL,
    uuid character varying(255) NOT NULL,
    connection text NOT NULL,
    queue text NOT NULL,
    payload text NOT NULL,
    exception text NOT NULL,
    failed_at timestamp(0) without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);
    DROP TABLE public.failed_jobs;
       public         heap    postgres    false            �            1259    47389    failed_jobs_id_seq    SEQUENCE     {   CREATE SEQUENCE public.failed_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.failed_jobs_id_seq;
       public          postgres    false    215            I           0    0    failed_jobs_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.failed_jobs_id_seq OWNED BY public.failed_jobs.id;
          public          postgres    false    214            �            1259    47434    gerbang_validasis    TABLE     �   CREATE TABLE public.gerbang_validasis (
    gerbang_id bigint NOT NULL,
    nama_gerbang character varying(255) NOT NULL,
    terminal_id bigint NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
 %   DROP TABLE public.gerbang_validasis;
       public         heap    postgres    false            �            1259    47433     gerbang_validasis_gerbang_id_seq    SEQUENCE     �   CREATE SEQUENCE public.gerbang_validasis_gerbang_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 7   DROP SEQUENCE public.gerbang_validasis_gerbang_id_seq;
       public          postgres    false    223            J           0    0     gerbang_validasis_gerbang_id_seq    SEQUENCE OWNED BY     e   ALTER SEQUENCE public.gerbang_validasis_gerbang_id_seq OWNED BY public.gerbang_validasis.gerbang_id;
          public          postgres    false    222            �            1259    47365 
   migrations    TABLE     �   CREATE TABLE public.migrations (
    id integer NOT NULL,
    migration character varying(255) NOT NULL,
    batch integer NOT NULL
);
    DROP TABLE public.migrations;
       public         heap    postgres    false            �            1259    47364    migrations_id_seq    SEQUENCE     �   CREATE SEQUENCE public.migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.migrations_id_seq;
       public          postgres    false    210            K           0    0    migrations_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.migrations_id_seq OWNED BY public.migrations.id;
          public          postgres    false    209            �            1259    47382    password_reset_tokens    TABLE     �   CREATE TABLE public.password_reset_tokens (
    email character varying(255) NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp(0) without time zone
);
 )   DROP TABLE public.password_reset_tokens;
       public         heap    postgres    false            �            1259    47414 	   penggunas    TABLE     5  CREATE TABLE public.penggunas (
    pengguna_id bigint NOT NULL,
    nama_pengguna character varying(255) NOT NULL,
    nomor_kartu_prepaid character varying(255) NOT NULL,
    saldo_kartu numeric(10,2) NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
    DROP TABLE public.penggunas;
       public         heap    postgres    false            �            1259    47413    penggunas_pengguna_id_seq    SEQUENCE     �   CREATE SEQUENCE public.penggunas_pengguna_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.penggunas_pengguna_id_seq;
       public          postgres    false    219            L           0    0    penggunas_pengguna_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.penggunas_pengguna_id_seq OWNED BY public.penggunas.pengguna_id;
          public          postgres    false    218            �            1259    47402    personal_access_tokens    TABLE     �  CREATE TABLE public.personal_access_tokens (
    id bigint NOT NULL,
    tokenable_type character varying(255) NOT NULL,
    tokenable_id bigint NOT NULL,
    name character varying(255) NOT NULL,
    token character varying(64) NOT NULL,
    abilities text,
    last_used_at timestamp(0) without time zone,
    expires_at timestamp(0) without time zone,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
 *   DROP TABLE public.personal_access_tokens;
       public         heap    postgres    false            �            1259    47401    personal_access_tokens_id_seq    SEQUENCE     �   CREATE SEQUENCE public.personal_access_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 4   DROP SEQUENCE public.personal_access_tokens_id_seq;
       public          postgres    false    217            M           0    0    personal_access_tokens_id_seq    SEQUENCE OWNED BY     _   ALTER SEQUENCE public.personal_access_tokens_id_seq OWNED BY public.personal_access_tokens.id;
          public          postgres    false    216            �            1259    47425 	   terminals    TABLE     f  CREATE TABLE public.terminals (
    terminal_id bigint NOT NULL,
    scankartu_id bigint NOT NULL,
    nama_terminal character varying(255) NOT NULL,
    lokasi_terminal character varying(255) NOT NULL,
    waktu_checkin timestamp(0) without time zone NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
    DROP TABLE public.terminals;
       public         heap    postgres    false            �            1259    47424    terminals_terminal_id_seq    SEQUENCE     �   CREATE SEQUENCE public.terminals_terminal_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.terminals_terminal_id_seq;
       public          postgres    false    221            N           0    0    terminals_terminal_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.terminals_terminal_id_seq OWNED BY public.terminals.terminal_id;
          public          postgres    false    220            �            1259    47441 
   transaksis    TABLE     a  CREATE TABLE public.transaksis (
    transaksi_id bigint NOT NULL,
    waktu_checkout timestamp(0) without time zone,
    gerbang_checkin_id bigint NOT NULL,
    gerbang_checkout_id bigint,
    pengguna_id bigint NOT NULL,
    tarif numeric(10,2) NOT NULL,
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
    DROP TABLE public.transaksis;
       public         heap    postgres    false            �            1259    47440    transaksis_transaksi_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaksis_transaksi_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 2   DROP SEQUENCE public.transaksis_transaksi_id_seq;
       public          postgres    false    225            O           0    0    transaksis_transaksi_id_seq    SEQUENCE OWNED BY     [   ALTER SEQUENCE public.transaksis_transaksi_id_seq OWNED BY public.transaksis.transaksi_id;
          public          postgres    false    224            �            1259    47372    users    TABLE     x  CREATE TABLE public.users (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    email_verified_at timestamp(0) without time zone,
    password character varying(255) NOT NULL,
    remember_token character varying(100),
    created_at timestamp(0) without time zone,
    updated_at timestamp(0) without time zone
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    47371    users_id_seq    SEQUENCE     u   CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    212            P           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    211            �           2604    47393    failed_jobs id    DEFAULT     p   ALTER TABLE ONLY public.failed_jobs ALTER COLUMN id SET DEFAULT nextval('public.failed_jobs_id_seq'::regclass);
 =   ALTER TABLE public.failed_jobs ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215            �           2604    47437    gerbang_validasis gerbang_id    DEFAULT     �   ALTER TABLE ONLY public.gerbang_validasis ALTER COLUMN gerbang_id SET DEFAULT nextval('public.gerbang_validasis_gerbang_id_seq'::regclass);
 K   ALTER TABLE public.gerbang_validasis ALTER COLUMN gerbang_id DROP DEFAULT;
       public          postgres    false    223    222    223            �           2604    47368    migrations id    DEFAULT     n   ALTER TABLE ONLY public.migrations ALTER COLUMN id SET DEFAULT nextval('public.migrations_id_seq'::regclass);
 <   ALTER TABLE public.migrations ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    210    209    210            �           2604    47417    penggunas pengguna_id    DEFAULT     ~   ALTER TABLE ONLY public.penggunas ALTER COLUMN pengguna_id SET DEFAULT nextval('public.penggunas_pengguna_id_seq'::regclass);
 D   ALTER TABLE public.penggunas ALTER COLUMN pengguna_id DROP DEFAULT;
       public          postgres    false    219    218    219            �           2604    47405    personal_access_tokens id    DEFAULT     �   ALTER TABLE ONLY public.personal_access_tokens ALTER COLUMN id SET DEFAULT nextval('public.personal_access_tokens_id_seq'::regclass);
 H   ALTER TABLE public.personal_access_tokens ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    217    217            �           2604    47428    terminals terminal_id    DEFAULT     ~   ALTER TABLE ONLY public.terminals ALTER COLUMN terminal_id SET DEFAULT nextval('public.terminals_terminal_id_seq'::regclass);
 D   ALTER TABLE public.terminals ALTER COLUMN terminal_id DROP DEFAULT;
       public          postgres    false    220    221    221            �           2604    47444    transaksis transaksi_id    DEFAULT     �   ALTER TABLE ONLY public.transaksis ALTER COLUMN transaksi_id SET DEFAULT nextval('public.transaksis_transaksi_id_seq'::regclass);
 F   ALTER TABLE public.transaksis ALTER COLUMN transaksi_id DROP DEFAULT;
       public          postgres    false    225    224    225            �           2604    47375    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    212    211    212            8          0    47390    failed_jobs 
   TABLE DATA           a   COPY public.failed_jobs (id, uuid, connection, queue, payload, exception, failed_at) FROM stdin;
    public          postgres    false    215   �S       @          0    47434    gerbang_validasis 
   TABLE DATA           j   COPY public.gerbang_validasis (gerbang_id, nama_gerbang, terminal_id, created_at, updated_at) FROM stdin;
    public          postgres    false    223   T       3          0    47365 
   migrations 
   TABLE DATA           :   COPY public.migrations (id, migration, batch) FROM stdin;
    public          postgres    false    210   ZT       6          0    47382    password_reset_tokens 
   TABLE DATA           I   COPY public.password_reset_tokens (email, token, created_at) FROM stdin;
    public          postgres    false    213   U       <          0    47414 	   penggunas 
   TABLE DATA           y   COPY public.penggunas (pengguna_id, nama_pengguna, nomor_kartu_prepaid, saldo_kartu, created_at, updated_at) FROM stdin;
    public          postgres    false    219   :U       :          0    47402    personal_access_tokens 
   TABLE DATA           �   COPY public.personal_access_tokens (id, tokenable_type, tokenable_id, name, token, abilities, last_used_at, expires_at, created_at, updated_at) FROM stdin;
    public          postgres    false    217   WU       >          0    47425 	   terminals 
   TABLE DATA           �   COPY public.terminals (terminal_id, scankartu_id, nama_terminal, lokasi_terminal, waktu_checkin, created_at, updated_at) FROM stdin;
    public          postgres    false    221   tU       B          0    47441 
   transaksis 
   TABLE DATA           �   COPY public.transaksis (transaksi_id, waktu_checkout, gerbang_checkin_id, gerbang_checkout_id, pengguna_id, tarif, created_at, updated_at) FROM stdin;
    public          postgres    false    225   �U       5          0    47372    users 
   TABLE DATA           u   COPY public.users (id, name, email, email_verified_at, password, remember_token, created_at, updated_at) FROM stdin;
    public          postgres    false    212   V       Q           0    0    failed_jobs_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.failed_jobs_id_seq', 1, false);
          public          postgres    false    214            R           0    0     gerbang_validasis_gerbang_id_seq    SEQUENCE SET     N   SELECT pg_catalog.setval('public.gerbang_validasis_gerbang_id_seq', 2, true);
          public          postgres    false    222            S           0    0    migrations_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.migrations_id_seq', 8, true);
          public          postgres    false    209            T           0    0    penggunas_pengguna_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.penggunas_pengguna_id_seq', 1, false);
          public          postgres    false    218            U           0    0    personal_access_tokens_id_seq    SEQUENCE SET     L   SELECT pg_catalog.setval('public.personal_access_tokens_id_seq', 1, false);
          public          postgres    false    216            V           0    0    terminals_terminal_id_seq    SEQUENCE SET     G   SELECT pg_catalog.setval('public.terminals_terminal_id_seq', 2, true);
          public          postgres    false    220            W           0    0    transaksis_transaksi_id_seq    SEQUENCE SET     I   SELECT pg_catalog.setval('public.transaksis_transaksi_id_seq', 2, true);
          public          postgres    false    224            X           0    0    users_id_seq    SEQUENCE SET     :   SELECT pg_catalog.setval('public.users_id_seq', 2, true);
          public          postgres    false    211            �           2606    47398    failed_jobs failed_jobs_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.failed_jobs
    ADD CONSTRAINT failed_jobs_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.failed_jobs DROP CONSTRAINT failed_jobs_pkey;
       public            postgres    false    215            �           2606    47400 #   failed_jobs failed_jobs_uuid_unique 
   CONSTRAINT     ^   ALTER TABLE ONLY public.failed_jobs
    ADD CONSTRAINT failed_jobs_uuid_unique UNIQUE (uuid);
 M   ALTER TABLE ONLY public.failed_jobs DROP CONSTRAINT failed_jobs_uuid_unique;
       public            postgres    false    215            �           2606    47439 (   gerbang_validasis gerbang_validasis_pkey 
   CONSTRAINT     n   ALTER TABLE ONLY public.gerbang_validasis
    ADD CONSTRAINT gerbang_validasis_pkey PRIMARY KEY (gerbang_id);
 R   ALTER TABLE ONLY public.gerbang_validasis DROP CONSTRAINT gerbang_validasis_pkey;
       public            postgres    false    223            �           2606    47370    migrations migrations_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.migrations
    ADD CONSTRAINT migrations_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.migrations DROP CONSTRAINT migrations_pkey;
       public            postgres    false    210            �           2606    47388 0   password_reset_tokens password_reset_tokens_pkey 
   CONSTRAINT     q   ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (email);
 Z   ALTER TABLE ONLY public.password_reset_tokens DROP CONSTRAINT password_reset_tokens_pkey;
       public            postgres    false    213            �           2606    47423 .   penggunas penggunas_nomor_kartu_prepaid_unique 
   CONSTRAINT     x   ALTER TABLE ONLY public.penggunas
    ADD CONSTRAINT penggunas_nomor_kartu_prepaid_unique UNIQUE (nomor_kartu_prepaid);
 X   ALTER TABLE ONLY public.penggunas DROP CONSTRAINT penggunas_nomor_kartu_prepaid_unique;
       public            postgres    false    219            �           2606    47421    penggunas penggunas_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.penggunas
    ADD CONSTRAINT penggunas_pkey PRIMARY KEY (pengguna_id);
 B   ALTER TABLE ONLY public.penggunas DROP CONSTRAINT penggunas_pkey;
       public            postgres    false    219            �           2606    47409 2   personal_access_tokens personal_access_tokens_pkey 
   CONSTRAINT     p   ALTER TABLE ONLY public.personal_access_tokens
    ADD CONSTRAINT personal_access_tokens_pkey PRIMARY KEY (id);
 \   ALTER TABLE ONLY public.personal_access_tokens DROP CONSTRAINT personal_access_tokens_pkey;
       public            postgres    false    217            �           2606    47412 :   personal_access_tokens personal_access_tokens_token_unique 
   CONSTRAINT     v   ALTER TABLE ONLY public.personal_access_tokens
    ADD CONSTRAINT personal_access_tokens_token_unique UNIQUE (token);
 d   ALTER TABLE ONLY public.personal_access_tokens DROP CONSTRAINT personal_access_tokens_token_unique;
       public            postgres    false    217            �           2606    47432    terminals terminals_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.terminals
    ADD CONSTRAINT terminals_pkey PRIMARY KEY (terminal_id);
 B   ALTER TABLE ONLY public.terminals DROP CONSTRAINT terminals_pkey;
       public            postgres    false    221            �           2606    47446    transaksis transaksis_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.transaksis
    ADD CONSTRAINT transaksis_pkey PRIMARY KEY (transaksi_id);
 D   ALTER TABLE ONLY public.transaksis DROP CONSTRAINT transaksis_pkey;
       public            postgres    false    225            �           2606    47381    users users_email_unique 
   CONSTRAINT     T   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_unique UNIQUE (email);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_unique;
       public            postgres    false    212            �           2606    47379    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    212            �           1259    47410 8   personal_access_tokens_tokenable_type_tokenable_id_index    INDEX     �   CREATE INDEX personal_access_tokens_tokenable_type_tokenable_id_index ON public.personal_access_tokens USING btree (tokenable_type, tokenable_id);
 L   DROP INDEX public.personal_access_tokens_tokenable_type_tokenable_id_index;
       public            postgres    false    217    217            8      x������ � �      @   9   x�3�tO-JJ�KW0�4�4202�5��5�T04�22�25�&�e�e�iD��=... S��      3   �   x�e�A�0��5�tJA���d�� XL���	��Y}^!�
�BШ~+��Ga'��9�X�!��D>��ѱ�G?tlC��a�*���;�=��������p�v���z��b��P:�:AU�C�@��Pڦ-���bŞݳ�f���IWܰ+�6����I���(�ۂ#+�������{�      6      x������ � �      <      x������ � �      :      x������ � �      >   E   x�3�4�I-���K�Qp����N,�2���u,u-���L�LM��2�4B��3Ӊ"3c���� Q�%      B   :   x�3�4202�5��5�T04�22�25�4�4bC=��Xĸ�����eJ�I1z\\\ %�      5   �   x�u�M�0 ���Wx�lNbu�%Q�[�B��5'~�i��>��)x�<<�*�uG	P̐(��M%L�$�	0�р���p�5u"�]�D�t�8f�,-DG׏x�ə�{��c��D��>�w�\V=�y��b��CZ�4i����D�]��������@�{XI�N��	[��Փ�Vlj���@C�     